#include <stdio.h>                                                            // standard C functions
#include <stdlib.h>                                                           // malloc(), realloc(), free()
#include <string.h>                                                           // memcpy()
#include <curl/curl.h>                                                        // HTTP GET to Agent

#include <cligen/cligen.h>                                                    // CLIgen definitions
#include <clixon/clixon.h>                                                    // Clixon plugin API


#define AGENT_STATE_URL "http://127.0.0.1:8080/internal/operational-state"      // Agent runs in same container as Clixon


typedef struct {
    char *data;                                                               // HTTP response body
    size_t size;                                                              // current response size
} response_buffer;


/* =====================================================================================
 * Receive HTTP response from Agent
 * ===================================================================================== */

static size_t
write_response(void *contents,
               size_t size,
               size_t nmemb,
               void *userp)
{
    size_t bytes = size * nmemb;                                              // bytes received in this call
    response_buffer *buffer = (response_buffer *)userp;                       // response buffer

    char *new_data = realloc(buffer->data,
                             buffer->size + bytes + 1);                        // enlarge response buffer

    if (new_data == NULL)
        return 0;                                                             // memory allocation failed

    buffer->data = new_data;

    memcpy(buffer->data + buffer->size,
           contents,
           bytes);                                                            // append received data

    buffer->size += bytes;                                                     // update total size
    buffer->data[buffer->size] = '\0';                                        // terminate XML string

    return bytes;
}


/* =====================================================================================
 * Get operational-state XML from Agent
 * ===================================================================================== */

static int
get_agent_state(char **xml)
{
    CURL *curl;
    CURLcode result;
    long http_code = 0;

    response_buffer buffer = {NULL, 0};

    buffer.data = malloc(1);                                                  // create empty buffer
    if (buffer.data == NULL)
        return -1;

    buffer.data[0] = '\0';

    curl = curl_easy_init();                                                  // create HTTP request
    if (curl == NULL) {
        free(buffer.data);
        return -1;
    }

    curl_easy_setopt(curl,
                     CURLOPT_URL,
                     AGENT_STATE_URL);                                        // Agent operational-state endpoint

    curl_easy_setopt(curl,
                     CURLOPT_WRITEFUNCTION,
                     write_response);                                         // receive Agent XML response

    curl_easy_setopt(curl,
                     CURLOPT_WRITEDATA,
                     &buffer);                                                // store response here

    curl_easy_setopt(curl,
                     CURLOPT_TIMEOUT,
                     5L);                                                     // do not wait indefinitely

    result = curl_easy_perform(curl);                                         // perform HTTP GET

    if (result != CURLE_OK) {
        curl_easy_cleanup(curl);
        free(buffer.data);
        return -1;
    }

    curl_easy_getinfo(curl,
                      CURLINFO_RESPONSE_CODE,
                      &http_code);                                            // get HTTP status code

    curl_easy_cleanup(curl);

    if (http_code != 200) {                                                   // Agent must return HTTP 200
        free(buffer.data);
        return -1;
    }

    *xml = buffer.data;                                                        // return Agent XML to caller

    return 0;
}


/* =====================================================================================
 * Clixon state callback
 * ===================================================================================== */

static int
sdwan_cpe_statedata(clixon_handle h,                                          // Clixon handle
                    cvec *nsc,                                                // namespace context
                    char *xpath,                                              // requested XPath
                    cxobj *xconfig)                                           // tree where state is added
{
    char *xml = NULL;

    if (get_agent_state(&xml) < 0)                                            // retrieve current state from Agent
        return 0;                                                             // Agent unavailable -> return no state

    if (clixon_xml_parse_string(xml,
                                YB_NONE,
                                0,
                                &xconfig,
                                0) < 0) {                                     // add Agent XML into Clixon state tree
        free(xml);
        return -1;
    }

    free(xml);                                                                // temporary HTTP response no longer needed

    return 0;
}

/* =====================================================================================
 * Clixon plugin registration
 * ===================================================================================== */

static clixon_plugin_api api = {
    "callback_plugin",                                                        // plugin name
    NULL,                                                                     // init callback not used
    NULL,                                                                     // start callback not used
    NULL,                                                                     // exit callback not used
    NULL,                                                                     // extension callback not used
    .ca_statedata = sdwan_cpe_statedata,                                      // operational-state callback
};


clixon_plugin_api *
clixon_plugin_init(clixon_handle h)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);                                    // initialize HTTP library

    return &api;                                                              // register plugin with Clixon
}
