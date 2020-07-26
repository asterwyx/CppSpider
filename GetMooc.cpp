#pragma once
#include "HttpLib.h"
#include <cstdio>
#include <stdio.h>
#include <regex>
#include <string.h>
#include "cJSON.h"
#include "Regex.h"
#define BIG_BUF_SIZE    (1024*1024)
#define FILTER_NUM      5

bool CheckFiltered(char pFilter[][MAX_NAME_LEN], int FilterNum, char* str);
void PrintcJSON(cJSON* item, bool IsFormatted);
int main()
{
    system("@chcp 65001 > nul");
    if (InitWSA() != 0)
    {
        fprintf(stderr, "WSAStartup failed!\n");
    }
    // 测试一下得到的主机ip是否正确
    PSESSION session = CreateSession("www.icourse163.org");
    strcpy_s(session->request->path, MAX_NAME_LEN, "/university/PKU");
    strcpy_s(session->response->BodyFileName, MAX_NAME_LEN, "PKU.html");
    char headers[][MAX_HEADER_LEN] = {
        "Accept: *",
        "Host: www.icourse163.org",
        "Connection: keep-alive",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"
    };
    for (int i = 0; i < 4; i++)
    {
        AddHeader(session->request, headers[i]);
    }
    int status = HttpRequest(session);
    for (int i = 0; i < 5; i++)
    {
        char NewBody[MAX_NAME_LEN];
        sprintf_s(NewBody, "schoolId=13001&p=%d&psize=20&type=1&courseStatus=30", i + 1);
        char NewFileName[MAX_NAME_LEN];
        sprintf_s(NewFileName, "PKU%d.json", i + 1);
        NextRequest(session, "/web/j/courseBean.getCourseListBySchoolId.rpc", METHOD::POST, NewBody, NewFileName);
        HttpRequest(session);
    }
    Dispose();
    // 开始处理得到的数据
    char FileName[MAX_NAME_LEN];
    char* BigBuffer = (char*)malloc(BIG_BUF_SIZE);
    if (BigBuffer == NULL)
    {
        fprintf(stderr, "Can't get a big buffer");
    }
    cJSON* DataGot;
    DataGot = cJSON_CreateObject();
    cJSON* DataArray = cJSON_CreateArray();
    cJSON_AddItemToObject(DataGot, "data", DataArray);
    cJSON* source;
    cJSON* SourceArray;
    cJSON* ArrayItem;
    cJSON* DataPiece;
    char PiecePath[MAX_NAME_LEN];
    char filter[FILTER_NUM][MAX_NAME_LEN] = {
        "id",
        "name",
        "startTime",
        "schoolName",
        "enrollCount"
    };
    for (int i = 0; i < 5; i++)
    {
        sprintf_s(FileName, MAX_NAME_LEN, "%sPKU%d.json", DATA_ROOT, i + 1);
        FILE* fp = fopen(FileName, "r");
        fgets(BigBuffer, BIG_BUF_SIZE, fp);
        // 解析这个文件
        source = cJSON_Parse(BigBuffer);
        SourceArray = cJSON_GetObjectItem(cJSON_GetObjectItem(source, "result"), "list");
        int ArraySize = cJSON_GetArraySize(SourceArray);
        for (int i = 0; i < ArraySize; i++)
        {
            ArrayItem = cJSON_GetArrayItem(SourceArray, i);
            DataPiece = cJSON_CreateObject();
            for (int i = 0; i < FILTER_NUM; i++)
            {
                cJSON_AddItemToObject(DataPiece, filter[i], cJSON_DetachItemFromObject(ArrayItem, filter[i]));
            }
            // 开始为每一条请求数据
            int id = cJSON_GetObjectItem(DataPiece, "id")->valueint;
            sprintf_s(PiecePath, MAX_NAME_LEN, "/course/PKU-%d", id);
            sprintf_s(FileName, MAX_NAME_LEN, "PKU-%d.html", id);
            NextRequest(session, PiecePath, METHOD::GET, NULL, FileName);
            HttpRequest(session);
            cJSON_AddItemToArray(DataArray, DataPiece);
        }
        cJSON_Delete(source);
        fclose(fp);
    }
    PrintcJSON(DataGot, true);
    char* String = cJSON_PrintUnformatted(DataGot);
    sprintf_s(FileName, MAX_NAME_LEN, "%sdata.json", DATA_ROOT);
    FILE* fp = fopen(FileName, "w");
    fputs(String, fp);
    free(String);
    fclose(fp);



    DestroySession(&session);
    return 0;
}

bool CheckFiltered(char pFilter[][MAX_NAME_LEN], int FilterNum, char* str)
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
    return	filtered;
}

void PrintcJSON(cJSON* item, bool IsFormatted)
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
