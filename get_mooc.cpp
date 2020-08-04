#include <cstdio>
#include <regex>
#include <cstring>

#include "cJSON.h"
#include "csr_main.h"
#define BIG_BUF_SIZE    (1024*1024)
#define FILTER_NUM      5
extern HANDLE gh_event_scheduler;

bool check_filtered(char pFilter[][MAX_NAME_LEN], int FilterNum, char* str);
void print_cJSON(cJSON* item, bool IsFormatted);
int main()
{
    uint64_t ret = csr_init();
    rc::parse_retcode(ret);
    if (ret != rc::SUCCESS) {
        return -1;
    } 
    p_session_t session = create_session("www.icourse163.org");
    strcpy_s(session->request->path, MAX_NAME_LEN, "/university/PKU");
    strcpy_s(session->response->body_filename, MAX_NAME_LEN, "PKU.html");
    char headers[][MAX_HEADER_LEN] = {
        "Accept: *",
        "Host: www.icourse163.org",
        "Connection: close",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"
    };
    for (int i = 0; i < 4; i++)
    {
        add_header(session->request, headers[i]);
    }
    int status = http_request(session);
    while (!csr::is_queue_empty())
    {
        Sleep(5);
    }
    for (int i = 0; i < 5; i++)
    {
        char NewBody[MAX_NAME_LEN];
        sprintf_s(NewBody, "schoolId=13001&p=%d&psize=20&type=1&courseStatus=30", i + 1);
        char NewFileName[MAX_NAME_LEN];
        sprintf_s(NewFileName, "PKU%d.json", i + 1);
        next_request(session, "/web/j/courseBean.getCourseListBySchoolId.rpc", method_t::POST, NewBody, NewFileName);
        http_request(session);
    }
    csr::signal_finish();
    WaitForSingleObject(gh_event_scheduler, INFINITE);
    // char FileName[MAX_NAME_LEN];
    // char* BigBuffer = (char*)malloc(BIG_BUF_SIZE);
    // if (BigBuffer == NULL)
    // {
    //     fprintf(stderr, "Can't get a big buffer");
    // }
    // cJSON* DataGot;
    // DataGot = cJSON_CreateObject();
    // cJSON* DataArray = cJSON_CreateArray();
    // cJSON_AddItemToObject(DataGot, "data", DataArray);
    // cJSON* source;
    // cJSON* SourceArray;
    // cJSON* ArrayItem;
    // cJSON* DataPiece;
    // char PiecePath[MAX_NAME_LEN];
    // char filter[FILTER_NUM][MAX_NAME_LEN] = {
    //     "id",
    //     "name",
    //     "startTime",
    //     "schoolName",
    //     "enrollCount"
    // };
    // for (int i = 0; i < 5; i++)
    // {
    //     sprintf_s(FileName, MAX_NAME_LEN, "%sPKU%d.json", DATA_ROOT, i + 1);
    //     FILE* fp = fopen(FileName, "r");
    //     fgets(BigBuffer, BIG_BUF_SIZE, fp);
    //     source = cJSON_Parse(BigBuffer);
    //     SourceArray = cJSON_GetObjectItem(cJSON_GetObjectItem(source, "result"), "list");
    //     int ArraySize = cJSON_GetArraySize(SourceArray);
    //     for (int i = 0; i < ArraySize; i++)
    //     {
    //         ArrayItem = cJSON_GetArrayItem(SourceArray, i);
    //         DataPiece = cJSON_CreateObject();
    //         for (int i = 0; i < FILTER_NUM; i++)
    //         {
    //             cJSON_AddItemToObject(DataPiece, filter[i], cJSON_DetachItemFromObject(ArrayItem, filter[i]));
    //         }
    //         int id = cJSON_GetObjectItem(DataPiece, "id")->valueint;
    //         sprintf_s(PiecePath, MAX_NAME_LEN, "/course/PKU-%d", id);
    //         sprintf_s(FileName, MAX_NAME_LEN, "PKU-%d.html", id);
    //         next_request(session, PiecePath, method_t::GET, NULL, FileName);
    //         http_request(session);
    //         cJSON_AddItemToArray(DataArray, DataPiece);
    //     }
    //     cJSON_Delete(source);
    //     fclose(fp);
    // }
    // print_cJSON(DataGot, true);
    // char* String = cJSON_PrintUnformatted(DataGot);
    // sprintf_s(FileName, MAX_NAME_LEN, "%sdata.json", DATA_ROOT);
    // FILE* fp = fopen(FileName, "w");
    // fputs(String, fp);
    // free(String);
    // fclose(fp);
    destroy_session(&session);
    return 0;
}

bool check_filtered(char pFilter[][MAX_NAME_LEN], int FilterNum, char* str)
{
    bool filtered = false;
    for (int i = 0; i < FilterNum; i++)
    {
        if (strcmp(pFilter[i], str) == 0)
        {
            filtered = true;
            break;
        }
    }
    return filtered;
}

void print_cJSON(cJSON* item, bool IsFormatted)
{
    char* PrintedString;
    if (IsFormatted)
    {
        PrintedString = cJSON_Print(item);
    }
    else
    {
        PrintedString = cJSON_PrintUnformatted(item);
    }
    printf("%s\n", PrintedString);
    free(PrintedString);
}
