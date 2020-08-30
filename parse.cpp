#include "csr_regex.h"
#include <regex>
#include "cJSON.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define DATA_ROOT           "../DataRoot/"
#define MAX_NAME_LEN        1024
char BigBuffer[MAX_BUF_SIZE];

int main()
{
    char FileName[MAX_NAME_LEN];
    char* result;
    sprintf_s(FileName, MAX_NAME_LEN, "%sdata.json", DATA_ROOT);
    FILE* fp = fopen(FileName, "r");
    fgets(BigBuffer, MAX_BUF_SIZE, fp);
    fclose(fp);
    cJSON* data = cJSON_Parse(BigBuffer);
    cJSON* DataArray = cJSON_GetObjectItem(data, "data");
    cJSON* DataPiece;
    int DataNum = cJSON_GetArraySize(DataArray);
    for (int i = 0; i < DataNum; i++)
    {
        DataPiece = cJSON_GetArrayItem(DataArray, i);
        int id = cJSON_GetObjectItem(DataPiece, "id")->valueint;
        sprintf_s(FileName, MAX_NAME_LEN, "%sPKU-%d.html", DATA_ROOT, id);
        fp = fopen(FileName, "r");
        fread(BigBuffer, 1, MAX_BUF_SIZE, fp);
        //fgets(BigBuffer, MAX_BUF_SIZE, fp);
        const char* next = GetCourseSummary(DataPiece, BigBuffer);
        next = GetCourseTarget(DataPiece, next);
        next = GetCourseReference(DataPiece, next);
        next = GetCourseOutline(DataPiece, next);
        fclose(fp);
        result = cJSON_Print(DataPiece);
        printf("%s\n", result);
        free(result);
    }
    result = cJSON_Print(data);
    sprintf_s(FileName, MAX_NAME_LEN, "%sdata.json", DATA_ROOT);
    fp = fopen(FileName, "w");
    fputs(result, fp);
    fclose(fp);
    free(result);
}