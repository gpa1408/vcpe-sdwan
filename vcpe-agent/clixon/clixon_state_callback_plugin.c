#include <stdio.h>                                                         
#include <string.h>                                                        
#include <dirent.h>                                                        
#include <limits.h>                                                         

#include <cligen/cligen.h>                                                  
#include <clixon/clixon.h>                                               

#define SDWAN_NS "urn:sdwan:cpe"                                           
#define KEY_DIR  "/var/lib/clixon/local-public-keys"                        // directory where agent.py stores tunnel public keys
#define NAT_DIR  "/var/lib/clixon/wan-link-nat-types"                       // directory where agent.py stores WAN NAT type state

static int
read_file(const char *path, char *buf, size_t buflen)                       // read first line of a file into buf
{
    FILE *fp;
    char *nl;

    fp = fopen(path, "r");                                                   // open file in read mode
    if (fp == NULL)
        return -1;

    if (fgets(buf, buflen, fp) == NULL) {                                    // read one line from file
        fclose(fp);
        return -1;
    }

    fclose(fp);

    nl = strchr(buf, '\n');                                                  // remove newline if file contains one
    if (nl)
        *nl = '\0';

    return 0;
}

static int
add_tunnel_public_keys(cxobj *xconfig)                                       // add tunnel local-public-key operational state
{
    DIR *dir;                                                               // directory pointer
    struct dirent *entry;                                                   // each entry represents one file inside the directory
    char filepath[PATH_MAX];                                                // full path to the .pub file
    char tunnel_name[32];                                                  // tunnel name extracted from filename
    char public_key[64];                                                   // public key read from file
    char xmlbuf[2048];                                                      // XML string returned to Clixon
    char *dot;                                                              // pointer used to find ".pub" in filename

    dir = opendir(KEY_DIR);                                                  // open public-key directory
    if (dir == NULL)
        return 0;                                                            // no key directory yet; not an error

    while ((entry = readdir(dir)) != NULL) {                                 // loop through files in KEY_DIR
        snprintf(tunnel_name, sizeof(tunnel_name), "%s", entry->d_name);     // copy filename into tunnel_name buffer

        dot = strstr(tunnel_name, ".pub");                                   // check for .pub extension
        if (dot == NULL)
            continue;                                                        // skip non-.pub files

        *dot = '\0';                                                         // remove .pub extension, leaving only tunnel name

        snprintf(filepath, sizeof(filepath), "%s/%s", KEY_DIR, entry->d_name); // build full file path

        if (read_file(filepath, public_key, sizeof(public_key)) < 0)          // read public key from file
            continue;                                                        // if reading fails, skip this file

        snprintf(xmlbuf, sizeof(xmlbuf),                                     // build XML operational data
                 "<sdwan xmlns=\"%s\">"
                   "<overlay>"
                     "<tunnel>"
                       "<name>%s</name>"
                       "<local-public-key>%s</local-public-key>"             // config false operational leaf
                     "</tunnel>"
                   "</overlay>"
                 "</sdwan>",
                 SDWAN_NS,
                 tunnel_name,
                 public_key);

        if (clixon_xml_parse_string(xmlbuf, YB_NONE, 0, &xconfig, 0) < 0) {  // pass XML string to Clixon
            closedir(dir);
            return -1;
        }
    }

    closedir(dir);                                                           // close directory after processing all files
    return 0;
}

static int
add_wan_nat_types(cxobj *xconfig)                                            // add WAN-link nat-type operational state
{
    DIR *dir;                                                               // directory pointer
    struct dirent *entry;                                                   // each entry represents one file inside the directory
    char filepath[PATH_MAX];                                                // full path to the .nat file
    char wan_name[32];                                                     // WAN-link name extracted from filename
    char nat_type[32];                                                      // NAT type read from file
    char xmlbuf[2048];                                                      // XML string returned to Clixon
    char *dot;                                                              // pointer used to find ".nat" in filename

    dir = opendir(NAT_DIR);                                                  // open NAT state directory
    if (dir == NULL)
        return 0;                                                            // no NAT directory yet; not an error

    while ((entry = readdir(dir)) != NULL) {                                 // loop through files in NAT_DIR
        snprintf(wan_name, sizeof(wan_name), "%s", entry->d_name);           // copy filename into wan_name buffer

        dot = strstr(wan_name, ".nat");                                      // check for .nat extension
        if (dot == NULL)
            continue;                                                        // skip non-.nat files

        *dot = '\0';                                                         // remove .nat extension, leaving only WAN-link name

        snprintf(filepath, sizeof(filepath), "%s/%s", NAT_DIR, entry->d_name); // build full file path

        if (read_file(filepath, nat_type, sizeof(nat_type)) < 0)             // read NAT type from file
            continue;                                                        // if reading fails, skip this file

        snprintf(xmlbuf, sizeof(xmlbuf),                                     // build XML operational data
                 "<sdwan xmlns=\"%s\">"
                   "<interfaces>"
                     "<underlay>"
                       "<wan-link>"
                         "<name>%s</name>"
                         "<nat-type>%s</nat-type>"                          // config false operational leaf
                       "</wan-link>"
                     "</underlay>"
                   "</interfaces>"
                 "</sdwan>",
                 SDWAN_NS,
                 wan_name,
                 nat_type);

        if (clixon_xml_parse_string(xmlbuf, YB_NONE, 0, &xconfig, 0) < 0) {  // pass XML string to Clixon
            closedir(dir);
            return -1;
        }
    }

    closedir(dir);                                                           // close directory after processing all files
    return 0;
}

static int
sdwan_cpe_statedata(clixon_handle h,                                         // h = Clixon handle
                    cvec *nsc,                                               // nsc = namespace context
                    char *xpath,                                             // xpath = requested XPath filter
                    cxobj *xconfig)                                          // xconfig = XML tree where plugin adds state data
{

    if (add_tunnel_public_keys(xconfig) < 0)                                  // add tunnel local-public-key state
        return -1;

    if (add_wan_nat_types(xconfig) < 0)                                       // add WAN-link NAT type state
        return -1;

    return 0;
}

static clixon_plugin_api api = {
    "callback_plugin",                                                        // plugin name shown in Clixon/plugin logs
    NULL,                                                                     // init callback not used
    NULL,                                                                     // start callback not used
    NULL,                                                                     // exit callback not used
    NULL,                                                                     // extension callback not used
    .ca_statedata = sdwan_cpe_statedata,                                      // register backend state callback
};

clixon_plugin_api *
clixon_plugin_init(clixon_handle h)                                           // required entry function; Clixon looks for this name
{
    return &api;                                                              // return plugin API structure to Clixon
}
