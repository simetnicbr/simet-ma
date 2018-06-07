#include "tcp.h"
#include "report.h"
#include "logger.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>

#include <sys/epoll.h>

#include <json-c/json.h>
#include <curl/curl.h>
#include <libubox/usock.h>
#include "libubox/utils.h"

#define TIMEVAL_MICROSECONDS(tv) ((tv.tv_sec * 1e6L) + tv.tv_usec)

int maxConn = 6;
int sockList[6];

/* Internal functions */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
int message_send(int socket, int timeout, void *message, size_t len);
int create_measure_socket(char *, char *, char *);
int send_tcp(int sockfd, char *message, int len);
int sendUploadPackets();
static int convert_family(int);

int tcp_client_run(MeasureContext ctx)
{

    DEBUG_LOG("Running TCP Client");

    CURL *curl;
    CURLcode res;
    long statusCode;

    curl_global_init(CURL_GLOBAL_ALL);

    // Get curl handle
    curl = curl_easy_init();
    if (curl)
    {

        DEBUG_LOG("Sending request /setup");

        struct curl_slist *slist = NULL;

        // Set URL
        char setup[] = "/setup";
        // +1 for '\0'
        int urlSize = strlen(ctx.control_url) + strlen(setup) + 1;
        char setupURL[urlSize];
        snprintf(setupURL, urlSize, "%s%s", ctx.control_url, setup);

        curl_easy_setopt(curl, CURLOPT_URL, setupURL);

        // Add Authorization Header with JWT -- +14 = Authorization -- +1 = '\0'
        int headerSize = 14 + strlen(ctx.token) + 1;
        char authHeader[headerSize];
        snprintf(authHeader, headerSize, "Authorization:%s", ctx.token);
        slist = curl_slist_append(slist, authHeader);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

        // Perform the request, res will get the curl return code
        res = curl_easy_perform(curl);
        // If curl failed to perform request
        if (res != CURLE_OK)
        {
            WARNING_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
            return -1;
        }

        // Get Status Code in Response
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);

        // Check if Status Code is 204 (OK - No Content)
        if (statusCode != 204)
        {
            WARNING_LOG("statusCode(%li) != 204", statusCode);
            return -1;
        }

        curl_easy_reset(curl);

        DEBUG_LOG("Creating measure connections");

        // Create measure sockets
        for (int i = 0; i < maxConn; i++)
        {
            int m_socket = create_measure_socket(ctx.host_name, ctx.port, ctx.token);
            if (m_socket == -1)
            {
                WARNING_LOG("m_socket == -1");
            }
            sockList[i] = m_socket;
        }

        // Send /start-upload
        DEBUG_LOG("Sending request /start-upload");
        // Set URL
        char startUpload[] = "/start-upload";
        urlSize = strlen(ctx.control_url) + strlen(startUpload) + 1;
        char startUploadURL[urlSize];
        snprintf(startUploadURL, urlSize, "%s%s", ctx.control_url, startUpload);
        curl_easy_setopt(curl, CURLOPT_URL, startUploadURL);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

        // Perform the request, res will get the curl return code
        res = curl_easy_perform(curl);
        // If curl failed to perform request
        if (res != CURLE_OK)
        {
            WARNING_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
            return -1;
        }

        // Get Status Code in Response
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);

        // Check if Status Code is 204 (OK - No Content)
        if (statusCode != 204)
        {
            WARNING_LOG("statusCode(%li) != 204", statusCode);
            return -1;
        }

        curl_easy_reset(curl);

        // Start TCP Upload
        DEBUG_LOG("Sending measure packets");
        sendUploadPackets();

        // Send /stop-upload
        DEBUG_LOG("Sending request /stop-upload");

        // Set URL
        char stopUpload[] = "/finish-upload";
        urlSize = strlen(ctx.control_url) + strlen(stopUpload) + 1;
        char stopUploadURL[urlSize];
        snprintf(stopUploadURL, urlSize, "%s%s", ctx.control_url, stopUpload);
        curl_easy_setopt(curl, CURLOPT_URL, stopUploadURL);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

        // Perform the request, res will get the curl return code
        res = curl_easy_perform(curl);
        // If curl failed to perform request
        if (res != CURLE_OK)
        {
            WARNING_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
            return -1;
        }

        // Get Status Code in Response
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);

        // Check if Status Code is 204 (OK - No Content)
        if (statusCode != 204)
        {
            WARNING_LOG("statusCode(%li) != 204", statusCode);
            return -1;
        }

        curl_easy_reset(curl);

        // Send /start-download
        DEBUG_LOG("Sending request /start-download");
        // Set URL
        char startDownload[] = "/start-download";
        urlSize = strlen(ctx.control_url) + strlen(startDownload) + 1;
        char startDownloadURL[urlSize];
        snprintf(startDownloadURL, urlSize, "%s%s", ctx.control_url, startDownload);
        curl_easy_setopt(curl, CURLOPT_URL, startDownloadURL);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

        // Perform the request, res will get the curl return code
        res = curl_easy_perform(curl);
        // If curl failed to perform request
        if (res != CURLE_OK)
        {
            WARNING_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
            return -1;
        }

        // Get Status Code in Response
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);

        // Check if Status Code is 204 (OK - No Content)
        if (statusCode != 204)
        {
            WARNING_LOG("statusCode(%li) != 204", statusCode);
            return -1;
        }

        curl_easy_reset(curl);

        ///////////////////////////////////////////////////
        fd_set set_master;
        FD_ZERO(&set_master);
        int max_tcp_socket = 0;

        for (int i = 0; i < maxConn; i++)
        {
            FD_SET(sockList[i], &set_master);
            if (sockList[i] > max_tcp_socket)
            {
                max_tcp_socket = sockList[i];
            }
        }

        int bytes_recv = 0, i;
        struct timeval tv_cur, tv_start, tv_stop_test, tv_select;
        char buffer[1400];
        char *result = NULL;
        fd_set rset;
        uint64_t total = 0;
        int rCounter = 0;
        int maxResults = 20;
        DownResult *downloadResults = malloc(sizeof(DownResult) * maxResults);

        /***** RECEIVE TCP DOWNLOAD PACKAGES FROM SERVER *****/
        gettimeofday(&tv_cur, NULL);
        tv_start.tv_usec = tv_cur.tv_usec;
        tv_start.tv_sec = tv_cur.tv_sec;
        tv_stop_test.tv_usec = tv_cur.tv_usec;
        tv_stop_test.tv_sec = tv_cur.tv_sec + (long)10 + 1;

        while (timercmp(&tv_cur, &tv_stop_test, <) && (rCounter < maxResults))
        {
            tv_select.tv_sec = tv_stop_test.tv_sec - tv_cur.tv_sec;
            tv_select.tv_usec = 0;

            // Necessário copiar toda vez pois o select 'zera' o fd_count
            memcpy(&rset, &set_master, sizeof(fd_set));
            if (select((int)(max_tcp_socket + 1), &rset, NULL, NULL, &tv_select) > 0)
            {
                for (i = 0; i < 6; i++)
                {
                    if (FD_ISSET(sockList[i], &rset))
                    {
                        bytes_recv = recv(sockList[i], buffer, 1400, 0);
                        if (bytes_recv > 0)
                        {
                            total += bytes_recv;
                        }
                    }
                }
            }

            // intervalS = interval in seconds (0.5s)
            // k = 1024
            // 8 = 1 byte is 8 bits
            if ((TIMEVAL_MICROSECONDS(tv_cur) - TIMEVAL_MICROSECONDS(tv_start)) > 500000)
            {
                // rCounter < maxResults or downloadResults will seg fault
                downloadResults[rCounter].sequence = rCounter + 1;
                downloadResults[rCounter].bits = total * 8;
                downloadResults[rCounter++].intervalMs = 500;

                //uint64_t kbps = total / 64; // 64 => (bytes * 8) / (0.5 * 1024)
                //DEBUG_LOG("%" PRIu64 " kbps - counter: %" PRIu32 " ", kbps, rCounter);

                total = 0;
                tv_start.tv_usec = tv_cur.tv_usec;
                tv_start.tv_sec = tv_cur.tv_sec;
            }
            gettimeofday(&tv_cur, NULL);
        }
        ///////////////////////////////////////////////////

        // Send /finish-download
        DEBUG_LOG("Sending request /finish-download");

        // Set URL
        char finishDownload[] = "/finish-download";
        urlSize = strlen(ctx.control_url) + strlen(finishDownload) + 1;
        char finishDownloadURL[urlSize];
        snprintf(finishDownloadURL, urlSize, "%s%s", ctx.control_url, finishDownload);
        curl_easy_setopt(curl, CURLOPT_URL, finishDownloadURL);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

        // Perform the request, res will get the curl return code
        res = curl_easy_perform(curl);
        // If curl failed to perform request
        if (res != CURLE_OK)
        {
            WARNING_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
            return -1;
        }

        // Get Status Code in Response
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);

        // Check if Status Code is 204 (OK - No Content)
        if (statusCode != 204)
        {
            WARNING_LOG("statusCode(%li) != 204", statusCode);
            return -1;
        }

        curl_easy_reset(curl);

        DEBUG_LOG("Sending request /result-upload");

        // Get Upload Results
        struct MemoryStruct chunk;
        chunk.memory = malloc(1); /* will be grown as needed by the realloc above */
        chunk.size = 0;           /* no data at this point */

        // Set URL
        char resultUpload[] = "/result-upload";
        urlSize = strlen(ctx.control_url) + strlen(resultUpload) + 1;
        char resultUploadURL[urlSize];
        snprintf(resultUploadURL, urlSize, "%s%s", ctx.control_url, resultUpload);
        curl_easy_setopt(curl, CURLOPT_URL, resultUploadURL);
        /* send all data to this function  */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

        // Perform the request, res will get the curl return code
        res = curl_easy_perform(curl);
        // If curl failed to perform request
        if (res != CURLE_OK)
        {
            WARNING_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
            return -1;
        }

        // Get Status Code in Response
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);

        // Check if Status Code is 200 (OK)
        if (statusCode != 200)
        {
            WARNING_LOG("statusCode(%li) != 204", statusCode);
            return -1;
        }

        curl_easy_cleanup(curl);

        curl_slist_free_all(slist);

        json_object *j_obj_upload = json_tokener_parse(chunk.memory);
        json_object *report_obj;

        report_obj = createReport(j_obj_upload, downloadResults, rCounter);

        OUTPUT("%s", json_object_to_json_string(report_obj));

        free(chunk.memory);
    }

    curl_global_cleanup();

    return 0;
}

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL)
    {
        /* out of memory! */
        WARNING_LOG("not enough memory (realloc returned NULL)");
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int message_send(int socket, int timeout, void *message, size_t len)
{
    int send_size = 0, send_total = 0;
    int fd_ready = 0;
    fd_set wset, wset_master;
    struct timeval tv_timeo;

    FD_ZERO(&wset_master);
    FD_SET((unsigned long)socket, &wset_master);

    tv_timeo.tv_sec = timeout;
    tv_timeo.tv_usec = 0;

    do
    {
        memcpy(&wset, &wset_master, sizeof(wset_master));

        fd_ready = select(socket + 1, NULL, &wset, NULL, &tv_timeo);

        if (fd_ready <= 0)
        {
            WARNING_LOG("select: %i", fd_ready);
        }
        else
        {
            if (FD_ISSET((unsigned long)socket, &wset))
            {
                send_size = send(socket, message + send_total, len - (unsigned long)send_total, 0);
                send_total += send_size;

                if ((unsigned long)send_total == len)
                {
                    return send_size;
                }

                WARNING_LOG("send_total different then expected!");
            }
            else
            {
                WARNING_LOG("socket not in wset!");
            }
        }
    } while ((tv_timeo.tv_sec > 0) && (tv_timeo.tv_usec > 0));
    return -1;
}

int create_measure_socket(char *host, char *port, char *token)
{
    int fd_measure;

    struct sockaddr_storage remote_addr_control;
    memset(&remote_addr_control, 0, sizeof(struct sockaddr_storage));
    fd_measure = usock_inet_timeout(USOCK_TCP, host, port, &remote_addr_control, 2000);
    if (fd_measure < 0)
    {
        WARNING_LOG("usock_inet_timeout fd_measure: %i", fd_measure);
        return -1;
    }

    int fd_ready = usock_wait_ready(fd_measure, 5000);
    if (fd_ready != 0)
    {
        WARNING_LOG("usock_wait_ready fd_ready: %i", fd_ready);
        return -1;
    }

    uint32_t jwtSize = cpu_to_be32(strlen(token));

    int ret_socket = message_send(fd_measure, 10, &jwtSize, sizeof(uint32_t));
    if (ret_socket <= 0)
    {
        WARNING_LOG("message_send problem");
        return -1;
    }

    ret_socket = message_send(fd_measure, 10, token, strlen(token));
    if (ret_socket <= 0)
    {
        WARNING_LOG("message_send problem");
        return -1;
    }

    return fd_measure;
}

int send_tcp(int sockfd, char *message, int len)
{
    int total = 0;
    int bytesleft = len;
    int n;

    while (total < len)
    {
        n = send(sockfd, message + total, bytesleft, 0);
        if (n == -1)
            break;
        else
        {
            total += n;
            bytesleft -= n;
        }
    }

    if (total < len)
        return -1;
    else
        return total;
}

int sendUploadPackets()
{
    fd_set set_master;

    FD_ZERO(&set_master);

    int max_tcp_socket = 0;
    int bufLen = 1400;
    int upTimeout = 10;
    int group = 3;

    for (int i = 0; i < maxConn; i++)
    {
        FD_SET(sockList[i], &set_master);
        if (sockList[i] > max_tcp_socket)
        {
            max_tcp_socket = sockList[i];
        }
    }

    struct timeval tv_cur, tv_stop_test, tv_select;
    int i, j;
    char *buff = malloc(bufLen);
    uint64_t counter = 0;
    fd_set wset;

    gettimeofday(&tv_cur, NULL);
    tv_stop_test.tv_usec = tv_cur.tv_usec;
    tv_stop_test.tv_sec = tv_cur.tv_sec + (long)upTimeout;

    while (timercmp(&tv_cur, &tv_stop_test, <))
    {
        tv_select.tv_sec = tv_stop_test.tv_sec - tv_cur.tv_sec;
        tv_select.tv_usec = 0;

        // Necessário copiar toda vez pois o select 'zera' o fd_count
        memcpy(&wset, &set_master, sizeof(fd_set));
        if (select((int)(max_tcp_socket + 1), NULL, &wset, NULL, &tv_select) > 0)
        {
            // Envia um grupo de pacotes seguidos antes de verificar o timeout do teste
            for (j = 0; j < group; j++)
            {
                for (i = 0; i < maxConn; i++)
                {
                    if (FD_ISSET(sockList[i], &wset))
                    {
                        send_tcp(sockList[i], buff, bufLen);
                        counter++;
                    }
                }
            }
        }
        gettimeofday(&tv_cur, NULL);
    };
    free(buff);
}

static int
convert_family(int family)
{
    if (family == 4)
        return USOCK_IPV4ONLY;
    else if (family == 6)
        return USOCK_IPV6ONLY;
    else
        return 0;
}