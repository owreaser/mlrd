#ifndef MALLARD_H
#define MALLARD_H

#include <argp.h>
#include <stdbool.h>

// Uncomment to disable SSID filtering
// #define DISABLE_SSID_FILTER

#define VERSION_STRING "0.1"

#define NAME_MAX_LENGTH 64

#define PERMISSIONS_DIR 0077
#define UMASK_FILE 0177

#define k_HELP 'h'
#define k_VERSION 'V'
#define k_REGISTER_KEY 1
#define k_REGISTER_KEY_REFERENCE 'l'
#define k_REGISTER_HOST 'H'
#define k_REGISTER_HOST_PORT 'p'
#define k_REGISTER_HOST_KEY 'k'
#define k_REGISTER_HOST_SSID 's'
#define k_REMOVE_KEY 2
#define k_REMOVE_HOST 'r'

static char USAGE[];
const char *VERSION;
static char doc[];
static struct argp_option ARGUMENTS[];

struct arguments {
  enum { DEFAULT, REGISTER_KEY, REGISTER_HOST, REMOVE_KEY, REMOVE_HOST } action;
  bool key_registration_use_reference;
  unsigned int host_registration_port;
  char *host_registration_key_name;
  char *host_registration_ssid;
  char *name;
};

static struct argp argp;

unsigned int clamp_port(int val);
void remove_key(char *name, const char *KEY_STORE_DIR);
void remove_host(char *name, char *ssid, const char *HOST_STORE_DIR);
static error_t parse_opt(int key, char *arg, struct argp_state *state);
char *str_concat(const char *str1, const char *str2, const char *pattern);
bool validate_name(char *name);
char *safe_ssid(char *ssid);
char *str_to_lower(char *str);
static int mkdir_exist_ok(const char* path, __mode_t mode);
int mkdir_recursive(const char *path, __mode_t mode);

#endif // MALLARD_H
