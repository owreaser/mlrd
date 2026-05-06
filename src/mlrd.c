#include <argp.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mlrd.h"

#define QUIT_USAGE fprintf(stderr, USAGE); exit(1);
#define UMASK_SET(mode) unsigned int old_umask = umask(mode)
#define UMASK_RESTORE umask(old_umask)

#define PRINTF_HOST_WITH_KEY "ssh %s -p %d -i %s/%s", host.username, host.port, KEY_STORE_DIR, host.key
#define PRINTF_HOST "ssh %s -p %d", host.username, host.port

static char USAGE[] = "Usage: mlrd [-h | --help] [-V | --version] [--remove-key=name] [-l | --list-hosts] [--list-keys]\n\
       mlrd --register-key <name> <private_key> [<public_key>] [--use-reference]\n\
       mlrd --register-host <name> <username> <host> [--port=<port>] [--key=<key_name>] [--ssid[=<ssid>]]\n\
       mlrd --remove-host=name [--ssid[=<ssid>]]\n\n";

const char *VERSION = "mlrd " VERSION_STRING;
static char doc[] = "Keeps track of your ssh keys and hosts.";
static struct argp_option ARGUMENTS[] = {
  { "help", k_HELP, 0, OPTION_NO_USAGE, "Shows this help message.", 1 },
  { "usage", 0, 0, OPTION_ALIAS, 0, 1 },
  { "version", k_VERSION, 0, OPTION_NO_USAGE, "Displays the current version of mlrd.", 1 },

  { "register-key", k_REGISTER_KEY, 0, OPTION_NO_USAGE, "Registers a new ssh key with mlrd.", 2 },
  { "use-reference", k_REGISTER_KEY_REFERENCE, 0, OPTION_NO_USAGE, "Create a symbolic link instead of a hard link for keys. Must be used with --register-key.", 3 },

  { "register-host", k_REGISTER_HOST, 0, OPTION_NO_USAGE, "Registers a new ssh-able host with mlrd, or edits an existing one with the same name.", 4 },
  { "port", k_REGISTER_HOST_PORT, "port", OPTION_NO_USAGE, "Specifies the port used for this host. Must be used with --register-host.", 5 },
  { "key", k_REGISTER_HOST_KEY, "key_name", OPTION_NO_USAGE, "Specifies which registered ssh key to use for this host. Must be used with --register-host.", 5 },
  { "ssid", k_REGISTER_HOST_SSID, "ssid", OPTION_NO_USAGE | OPTION_ARG_OPTIONAL, "Specifies if an alternate host address should be used for a hostname when on a specific network (case sensitive). Must be used with --register-host or --remove-host.", 5 },

  { "remove-key", k_REMOVE_KEY, "name", OPTION_NO_USAGE, "Removes an ssh key registered with mlrd.", 6 },
  { "remove-host", k_REMOVE_HOST, "name", OPTION_NO_USAGE, "Removes a host registered with mlrd. If an SSID is specified with --ssid=..., then only the host configuration corresponding to that SSID will be removed. Otherwise, all configurations for any SSID will be removed.", 6 },

  { "list-keys", k_LIST_KEYS, 0, OPTION_NO_USAGE, "Lists registered keys.", 7 },
  { "list-hosts", k_LIST_HOSTS, 0, OPTION_NO_USAGE, "Lists registered hosts.", 7 },
  { 0 }
};

#define ILA_LEN 5
char *inline_arguments[ILA_LEN] = {};

static struct argp argp = { ARGUMENTS, parse_opt, USAGE, doc, 0, 0, 0 };

#ifndef DISABLE_SSID_FILTER

char *get_ssid() {
  // "iw" isn't installed
  if (system("which iw > /dev/null 2>&1")) {
    fprintf(stderr, "mlrd: 'iw' not installed, can't get SSID\n");
    return NULL;
  }

  FILE *fp;

  fp = popen("iw dev | grep ssid | sed -n 's/.*ssid //p'", "r");
  if (fp == NULL) {
    fprintf(stderr, "mlrd: failed to get SSID\n");
    return NULL;
  }

  char *ssid = (char *)malloc(256);
  fgets(ssid, 255, fp);
  ssid[strlen(ssid) - 1] = '\0';
  pclose(fp);

  return safe_ssid(ssid);
}
#endif // DISABLE_SSID_FILTER

// string functions
bool str_starts_with(const char *haystack, const char *needle, int length) {
  return strncmp(needle, haystack, length) == 0;
}

char *str_concat(const char *str1, const char *str2, const char *pattern) {
  if (pattern == NULL) {
    pattern = "%s%s";
  }

  size_t size = snprintf(NULL, 0, pattern, str1, str2);
  char *buf = (char *)malloc(size + 1);
  snprintf(buf, size + 1, pattern, str1, str2);
  return buf;
}

char *str_to_lower(char *str) {
  for (int i = 0; str[i] != '\0'; i++) {
    str[i] = tolower(str[i]);
  }

  return str;
}

// file management
static int mkdir_exist_ok(const char* path, __mode_t mode) {
  struct stat st;
  errno = 0;

  if (mkdir(path, mode) == 0) { return 0; }
  if (errno != EEXIST || stat(path, &st) != 0) { return -1; }

  if (!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    return -1;
  }

  errno = 0;
  return 0;
}

int mkdir_recursive(const char *path, __mode_t mode) {
  char *_path = strdup(path);
  char *p;
  int result = -1;

  errno = 0;

  if (_path != NULL) {
    for (p = _path + 1; *p; p++) {
      if (*p == '/') {
        *p = '\0';
        if (mkdir_exist_ok(_path, mode) != 0) { break; }
        *p = '/';
      }
    }

    if (mkdir_exist_ok(_path, mode) == 0) { result = 0; }
  }

  free(_path);
  return result;
}

// util
struct host_data get_host(char *host, const char *HOST_STORE_DIR) {
  if (!validate_name(host, false)) {
    exit(1);
  }

  host = str_to_lower(host);

  char *host_filename = str_concat(HOST_STORE_DIR, host, "%s/%s");
  char *host_real;

  #ifndef DISABLE_SSID_FILTER
  char *ssid = get_ssid();
  char *ssid_filename = str_concat(host_filename, safe_ssid(ssid), "%s+%s");
  if (ssid != NULL && access(ssid_filename, F_OK) == 0) {
    host_real = ssid_filename;
  } else
  #endif // DISABLE_SSID_FILTER
  if (access(host_filename, F_OK) == 0) {
    host_real = host_filename;
  } else {
    fprintf(stderr, "mlrd: couldn't find host to connect: '%s'\n", host);
    exit(1);
  }

  FILE *fp = fopen(host_real, "r");

  if (fp == NULL) {
    fprintf(stderr, "mlrd: unable to open file '%s'\n", host_real);
    exit(1);
  }

  size_t _ = 0;
  char *user_line;
  getline(&user_line, &_, fp);
  user_line[strlen(user_line) - 1] = '\0'; // don't care about trailing newline

  _ = 0;
  char *port_str;
  getline(&port_str, &_, fp);
  port_str[strlen(port_str) - 1] = '\0'; // don't care about trailing newline
  unsigned int port = clamp_port(atoi(port_str));

  _ = 0;
  char *key_name;
  getline(&key_name, &_, fp);
  key_name[strlen(key_name) - 1] = '\0'; // don't care about trailing newline

  struct host_data data = {
    user_line, // username
    port, // port
    key_name, // key
  };

  return data;
}

unsigned int clamp_port(int val) {
  if (val > 0xffff) { return 0xffffU; }
  else if (val < 1) { return 1U; }
  return (unsigned int) val;
}

bool validate_name(char *name, bool silent) {
  int len = strlen(name);

  if (len < 1 || len > NAME_MAX_LENGTH) {
    fprintf(stderr, "mlrd: key/host name must be between 1-%d characters\n", NAME_MAX_LENGTH);
    return false;
  }

  name = str_to_lower(name);

  for (int i = 0; i < len; i++) {
    char chr = name[i];

    if ((chr >= 'a' && chr <= 'z') || (chr >= '0' && chr <= '9') || chr == '_' || chr == '-') {
      continue;
    }

    if (!silent) {
      fprintf(stderr, "mlrd: key/host name can only use a-z, 0-9, underscores, and hyphens, not '%c'\n", chr);
    }

    return false;
  }

  return true;
}

char *safe_ssid(char *ssid) {
  if (ssid == NULL) {
    return "";
  }

  for (int i = 0; ssid[i] != '\0'; i++) {
    char chr = tolower(ssid[i]);

    if ((chr >= 'a' && chr <= 'z') || (chr >= '0' && chr <= '9') || chr == '_' || chr == '.' || chr == '-') {
      continue;
    }

    ssid[i] = '_';
  }

  return ssid;
}

// arg parser
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;

  switch (key) {
    case k_HELP: printf(USAGE); argp_help(&argp, stdout, ARGP_HELP_LONG | ARGP_HELP_DOC, 0); exit(0);
    case k_VERSION: printf("%s\n", VERSION); exit(0);

    case k_REGISTER_KEY: if (arguments->action == DEFAULT) { arguments->action = REGISTER_KEY; } break;
    case k_REGISTER_KEY_REFERENCE: arguments->key_registration_use_reference = true; break;

    case k_REGISTER_HOST: if (arguments->action == DEFAULT) { arguments->action = REGISTER_HOST; } break;
    case k_REGISTER_HOST_PORT: arguments->host_registration_port = clamp_port(atoi(arg)); break;
    case k_REGISTER_HOST_KEY: arguments->host_registration_key_name = arg; break;
    case k_REGISTER_HOST_SSID: if (arg == NULL) { arguments->host_registration_ssid = get_ssid(); } else { arguments->host_registration_ssid = arg; } break;

    case k_REMOVE_KEY: if (arguments->action == DEFAULT) { arguments->action = REMOVE_KEY; arguments->name = arg; } break;
    case k_REMOVE_HOST: if (arguments->action == DEFAULT) { arguments->action = REMOVE_HOST; arguments->name = arg; } break;

    case k_LIST_KEYS: if (arguments->action == DEFAULT) { arguments->action = LIST_KEYS; } break;
    case k_LIST_HOSTS: if (arguments->action == DEFAULT) { arguments->action = LIST_HOSTS; } break;

    case ARGP_KEY_ARG:
      // keep track of order of cli arguments
      for (int i = 0; i < ILA_LEN; i++) {
        if (inline_arguments[i] == NULL) {
          inline_arguments[i] = arg;
          break;
        }
      }
      return 0;

    default: return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

// actions
void remove_key(char *name, const char *KEY_STORE_DIR) {
  if (validate_name(name, false)) {
    name = str_to_lower(name);
    char *priv_key_fname = str_concat(KEY_STORE_DIR, name, "%s/%s");
    char *pub_key_fname = str_concat(priv_key_fname, ".pub", NULL);

    remove(priv_key_fname);
    remove(pub_key_fname);

    printf("mlrd: deleted key '%s'\n", name);
  } else {
    fprintf(stderr, "mlrd: couldn't find key to remove: '%s'\n", name);
  }
}

void remove_host(char *name, char *ssid, const char *HOST_STORE_DIR) {
  if (validate_name(name, false)) {
    name = str_to_lower(name);

    if (ssid == NULL) {
      char *host_fname = str_concat(HOST_STORE_DIR, name, "%s/%s");
      remove(host_fname);
      printf("mlrd: deleted host '%s'\n", name);

      char *prefix = str_concat(name, "+", NULL);
      int prefix_length = strlen(prefix);

      // loop through files to delete others
      DIR *dir = opendir(HOST_STORE_DIR);
      struct dirent *ent;
      while ((ent = readdir(dir)) != NULL) {
        if (str_starts_with(ent->d_name, prefix, prefix_length)) {
          remove(str_concat(HOST_STORE_DIR, ent->d_name, "%s/%s"));
          printf("mlrd: deleted host '%s'\n", ent->d_name);
        }
      }
    } else {
      char *host_fname = str_concat(str_concat(HOST_STORE_DIR, name, "%s/%s"), ssid, "%s+%s");
      remove(host_fname);
      printf("mlrd: deleted host '%s+%s'\n", name, ssid);
    }
  } else {
    fprintf(stderr, "mlrd: couldn't find host to remove: '%s'\n", name);
  }
}

void list_keys(const char *KEY_STORE_DIR) {
  DIR *dir = opendir(KEY_STORE_DIR);
  struct dirent *ent;

  while ((ent = readdir(dir)) != NULL) {
    if (validate_name(ent->d_name, true)) {
      printf("%s\n", ent->d_name);
    }
  }
}

void list_hosts(const char *HOST_STORE_DIR) {
  DIR *dir = opendir(HOST_STORE_DIR);
  struct dirent *ent;

  while ((ent = readdir(dir)) != NULL) {
    if (ent->d_name[0] == '.') {
      continue;
    }

    printf("%s\n", ent->d_name);
  }
}

// main!!!
int main(int argc, char **argv) {
  struct arguments arguments = {
    DEFAULT, // action
    false, // key_registration_use_reference
    22, // host_registration_port
    "", // host_registration_key_name
    NULL, // host_registration_ssid
    NULL, // name
  };

  const char *CONFIG_DIR = str_concat(getenv("HOME"), "/.local/share/mallard", NULL);

  // file format: <keyname> (priv key) and <keyname>.pub (pub key), just normal ssh keys
  const char *KEY_STORE_DIR = str_concat(CONFIG_DIR, "/keys", NULL);

  // file format: <hostname>+<ssid> or <hostname>
  // file has 3 lines:
  // - username@hostname
  // - port (should be set, assume 22 if empty)
  // - key name
  const char *HOST_STORE_DIR = str_concat(CONFIG_DIR, "/hosts", NULL);

  if (mkdir_recursive(KEY_STORE_DIR, PERMISSIONS_DIR) != 0) { fprintf(stderr, "mlrd: unable to create directory %s\n", KEY_STORE_DIR); }
  if (mkdir_recursive(HOST_STORE_DIR, PERMISSIONS_DIR) != 0) { fprintf(stderr, "mlrd: unable to create directory %s\n", HOST_STORE_DIR); }

  argp_parse(&argp, argc, argv, ARGP_NO_HELP, 0, &arguments);

  // TODO: this should be a switch statement probably
  if (arguments.action == DEFAULT && argc > 1) {
    struct host_data host = get_host(inline_arguments[0], HOST_STORE_DIR);

    int length;
    if (host.key[0] != '\0') {
      length = snprintf(NULL, 0, PRINTF_HOST_WITH_KEY);
    } else {
      length = snprintf(NULL, 0, PRINTF_HOST);
    }

    char buf[length + 1];
    if (host.key[0] != '\0') {
      snprintf(buf, length + 1, PRINTF_HOST_WITH_KEY);
    } else {
      snprintf(buf, length + 1, PRINTF_HOST);
    }

    system(buf);
  } else if (arguments.action == REGISTER_KEY) {
    char *name = inline_arguments[0];

    if (!validate_name(name, false)) {
      exit(1);
    }

    name = str_to_lower(name);

    char *priv_key = inline_arguments[1];

    char *pub_key = inline_arguments[2];
    if (pub_key == NULL) {
      pub_key = str_concat(priv_key, ".pub", NULL);
    }

    // get real paths, expand . and .., etc
    char *priv_key_real = realpath(priv_key, NULL);
    char *pub_key_real = realpath(pub_key, NULL);

    // output files
    char *priv_key_output = str_concat(KEY_STORE_DIR, name, "%s/%s");
    char *pub_key_output = str_concat(priv_key_output, ".pub", NULL);

    // don't care if this doesn't work, we just wanna make sure there isn't an existing file
    remove(priv_key_output);
    remove(pub_key_output);

    // check if files exist
    if (access(priv_key_real, F_OK) != 0) {
      fprintf(stderr, "mlrd: private key doesn't exist: '%s'\n", priv_key_real);
      exit(1);
    } else if (!arguments.key_registration_use_reference && access(priv_key_real, R_OK) != 0) {
      fprintf(stderr, "mlrd: not permitted to read private key: '%s'\n", priv_key_real);
      exit(1);
    } else if (access(pub_key_real, F_OK) != 0) {
      fprintf(stderr, "mlrd: public key doesn't exist: '%s'\n", pub_key_real);
      exit(1);
    } else if (!arguments.key_registration_use_reference && access(pub_key_real, R_OK) != 0) {
      fprintf(stderr, "mlrd: not permitted to read public key: '%s'\n", pub_key_real);
      exit(1);
    }

    UMASK_SET(UMASK_FILE);

    int (*f_link)(const char*, const char*) = link;

    if (arguments.key_registration_use_reference) {
      f_link = symlink;
    }

    // create links
    if (f_link(priv_key_real, priv_key_output) != 0) {
      fprintf(stderr, "mlrd: unable to create link from '%s' to '%s'\n", priv_key_output, priv_key_real);
      exit(1);
    }

    if (f_link(pub_key_real, pub_key_output) != 0) {
      fprintf(stderr, "mlrd: unable to create link from '%s' to '%s'\n", pub_key_output, pub_key_real);
      exit(1);
    }

    UMASK_RESTORE;
    printf("mlrd: successfully registered key '%s'\n", name);
  } else if (arguments.action == REGISTER_HOST) {
    char *name = inline_arguments[0];

    if (!validate_name(name, false)) {
      exit(1);
    }

    name = str_to_lower(name);

    char *username = inline_arguments[1];

    for (int i = 0; username[i] != '\0'; i++) {
      char chr = username[i];
      if (chr == '@' || chr == '\n' || chr == ' ') {
        fprintf(stderr, "mlrd: username can't include the '%c' character\n", chr);
        exit(1);
      }
    }

    char *host = inline_arguments[2];

    char *filename;
    if (arguments.host_registration_ssid) {
      filename = str_concat(name, safe_ssid(arguments.host_registration_ssid), "%s+%s");
    } else {
      filename = name;
    }

    filename = str_concat(HOST_STORE_DIR, filename, "%s/%s");

    UMASK_SET(UMASK_FILE);
    FILE *fp = fopen(filename, "w");

    if (fp == NULL) {
      fprintf(stderr, "mlrd: unable to open file '%s'\n", filename);
      exit(1);
    }

    fprintf(fp, "%s@%s\n%d\n%s\n", username, host, arguments.host_registration_port, arguments.host_registration_key_name);
    fclose(fp);

    UMASK_RESTORE;

    printf("mlrd: successfully created host configuration '%s'\n", name);
  } else if (arguments.action == REMOVE_KEY) {
    remove_key(arguments.name, KEY_STORE_DIR);
  } else if (arguments.action == REMOVE_HOST) {
    remove_host(arguments.name, arguments.host_registration_ssid, HOST_STORE_DIR);
  } else if (arguments.action == LIST_KEYS) {
    list_keys(KEY_STORE_DIR);
  } else if (arguments.action == LIST_HOSTS) {
    list_hosts(HOST_STORE_DIR);
  } else {
    QUIT_USAGE
  }

  exit(0);
}
