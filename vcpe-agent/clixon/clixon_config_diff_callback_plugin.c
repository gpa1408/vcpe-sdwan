#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>

#include <cligen/cligen.h>

#include <clixon/clixon.h>
#include <clixon/clixon_backend.h>
#include <clixon/clixon_plugin.h>

#define PLUGIN_NAME "sdwan-agent-callback-plugin"

#define AGENT_VALIDATE_URL "http://127.0.0.1:8080/internal/clixon/validate-config-change"
#define AGENT_COMMIT_URL   "http://127.0.0.1:8080/internal/clixon/commit-config-change"

#define HTTP_TIMEOUT_SEC 10L


/*
 * Append one Clixon XML node into a cbuf.
 */
static int
append_xml_node(cbuf *cb, cxobj *x)
{
    if (x == NULL)
        return 0;

    if (clixon_xml2cbuf(cb, x, 0, 0, (char *)"", -1, 0) < 0)
        return -1;

    return 0;
}


/*
 * Append parent XML node of a changed node.
 *
 * Example:
 *   changed node = <static-address>192.168.1.20/24</static-address>
 *   parent node  = <wan-link>...</wan-link>
 */
static int
append_parent_xml_node(cbuf *cb, cxobj *x)
{
    cxobj *parent = NULL;

    if (x == NULL)
        return 0;

    parent = xml_parent(x);

    if (parent == NULL)
        parent = x;

    if (clixon_xml2cbuf(cb, parent, 0, 0, (char *)"", -1, 0) < 0)
        return -1;

    return 0;
}


/*
 * Append added or deleted nodes.
 */
static int
append_node_vector(cbuf *cb, const char *tag, cxobj **vec, size_t len)
{
    size_t i;

    cprintf(cb, "<%s>", tag);

    for (i = 0; i < len; i++) {
        cprintf(cb, "<node>");

        cprintf(cb, "<node-name>%s</node-name>",
                xml_name(vec[i]) ? xml_name(vec[i]) : "");

        cprintf(cb, "<data>");
        if (append_xml_node(cb, vec[i]) < 0)
            return -1;
        cprintf(cb, "</data>");

        cprintf(cb, "<parent-data>");
        if (append_parent_xml_node(cb, vec[i]) < 0)
            return -1;
        cprintf(cb, "</parent-data>");

        cprintf(cb, "</node>");
    }

    cprintf(cb, "</%s>", tag);

    return 0;
}


/*
 * Append changed old/new pairs.
 *
 * old value = transaction_scvec(td)
 * new value = transaction_tcvec(td)
 */
static int
append_changed_pairs(cbuf *cb, transaction_data td)
{
    cxobj **oldv;
    cxobj **newv;
    size_t len;
    size_t i;

    oldv = transaction_scvec(td);
    newv = transaction_tcvec(td);
    len  = transaction_clen(td);

    cprintf(cb, "<changed>");

    for (i = 0; i < len; i++) {
        cprintf(cb, "<change>");

        /*
         * Old value
         */
        cprintf(cb, "<old>");
        if (oldv && oldv[i]) {
            cprintf(cb, "<node-name>%s</node-name>",
                    xml_name(oldv[i]) ? xml_name(oldv[i]) : "");

            cprintf(cb, "<data>");
            if (append_xml_node(cb, oldv[i]) < 0)
                return -1;
            cprintf(cb, "</data>");

            cprintf(cb, "<parent-data>");
            if (append_parent_xml_node(cb, oldv[i]) < 0)
                return -1;
            cprintf(cb, "</parent-data>");
        }
        cprintf(cb, "</old>");

        /*
         * New value
         */
        cprintf(cb, "<new>");
        if (newv && newv[i]) {
            cprintf(cb, "<node-name>%s</node-name>",
                    xml_name(newv[i]) ? xml_name(newv[i]) : "");

            cprintf(cb, "<data>");
            if (append_xml_node(cb, newv[i]) < 0)
                return -1;
            cprintf(cb, "</data>");

            cprintf(cb, "<parent-data>");
            if (append_parent_xml_node(cb, newv[i]) < 0)
                return -1;
            cprintf(cb, "</parent-data>");
        }
        cprintf(cb, "</new>");

        cprintf(cb, "</change>");
    }

    cprintf(cb, "</changed>");

    return 0;
}


/*
 * Build XML transaction event sent to Python agent.
 */
static char *
build_transaction_xml(transaction_data td, const char *phase)
{
    cbuf *cb = NULL;
    char *payload = NULL;
    unsigned long long tid = 0;

    if (td != NULL)
        tid = (unsigned long long)transaction_id(td);

    cb = cbuf_new();
    if (cb == NULL)
        return NULL;

    cprintf(cb, "<clixon-config-transaction>");
    cprintf(cb, "<module>sdwan-cpe</module>");
    cprintf(cb, "<phase>%s</phase>", phase);
    cprintf(cb, "<transaction-id>%llu</transaction-id>", tid);

    if (append_node_vector(cb, "added",
                           transaction_avec(td),
                           transaction_alen(td)) < 0)
        goto done;

    if (append_node_vector(cb, "deleted",
                           transaction_dvec(td),
                           transaction_dlen(td)) < 0)
        goto done;

    if (append_changed_pairs(cb, td) < 0)
        goto done;

    cprintf(cb, "</clixon-config-transaction>");

    payload = strdup(cbuf_get(cb));

done:
    if (cb)
        cbuf_free(cb);

    return payload;
}


/*
 * Send XML payload to Python agent.
 */
static int
post_xml_to_agent(const char *url, const char *xml_payload)
{
    CURL *curl = NULL;
    CURLcode res;
    long http_code = 0;
    struct curl_slist *headers = NULL;
    int ret = -1;

    curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    headers = curl_slist_append(headers, "Content-Type: application/xml");
    headers = curl_slist_append(headers, "Accept: application/xml");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, xml_payload);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTP_TIMEOUT_SEC);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        goto done;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code >= 200 && http_code < 300)
        ret = 0;

done:
    if (headers)
        curl_slist_free_all(headers);

    if (curl)
        curl_easy_cleanup(curl);

    return ret;
}


/*
 * Common function used by validate and commit callbacks.
 */
static int
send_transaction_to_agent(const char *url, const char *phase, transaction_data td)
{
    char *payload = NULL;
    int ret = -1;

    payload = build_transaction_xml(td, phase);
    if (payload == NULL)
        goto done;

    ret = post_xml_to_agent(url, payload);

done:
    if (payload)
        free(payload);

    return ret;
}


/*
 * Validate callback.
 *
 * Python agent should call forwarder transaction API with:
 *   validate_only = true
 */
static int
sdwan_trans_validate(clixon_handle h, transaction_data td)
{
    (void)h;

    if (send_transaction_to_agent(AGENT_VALIDATE_URL, "validate", td) < 0) {
        clixon_err(OE_PLUGIN, 0, "SD-WAN agent validation failed or agent unreachable");
        return -1;
    }
    return 0;
}


/*
 * Commit callback.
 *
 * Python agent should call forwarder transaction API with:
 *   validate_only = false
 */
static int
sdwan_trans_commit(clixon_handle h, transaction_data td)
{
    (void)h;

    if (send_transaction_to_agent(AGENT_COMMIT_URL, "commit", td) < 0) {
        clixon_err(OE_PLUGIN, 0, "SD-WAN agent commit failed or agent unreachable");
        return -1;
    }
    return 0;
}


static int
sdwan_plugin_start(clixon_handle h)
{
    (void)h;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    return 0;
}


static int
sdwan_plugin_exit(clixon_handle h)
{
    (void)h;

    curl_global_cleanup();
    return 0;
}


clixon_plugin_api *
clixon_plugin_init(clixon_handle h);


static clixon_plugin_api api = {
    PLUGIN_NAME,
    clixon_plugin_init,
    sdwan_plugin_start,
    sdwan_plugin_exit,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,

    .ca_trans_validate = sdwan_trans_validate,
    .ca_trans_commit   = sdwan_trans_commit,
};


clixon_plugin_api *
clixon_plugin_init(clixon_handle h)
{
    (void)h;

    return &api;
}
