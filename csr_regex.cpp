#include "csr_regex.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
char TextBuffer[MAX_BUF_SIZE];

/**
 *  普通字符的* +是贪婪匹配，通配符的* +是最小匹配，?相当于匹配一个（除非遇到字符串结尾）
 */
// 要实现的元字符：* + ? . ^ ()
// 目前还有一个妥协，涉及到限定符就算只是限定前面一个字符，前面也要用子表达式符号括起来。
// 该正则表达式引擎不匹配重叠的匹配序列，也就是说同一个字符只会出现在一次的匹配里
// 不考虑转义字符，匹配到了返回一个结果指针，没有匹配到返回NULL
PMATCH_RESULT RegexMatch(const char* source, const char* pattern)
{
    PMATCH_RESULT result = CreateResult(); // 最后返回的结果
    PMATCH_PIECE tail = result->pieces, NewPiece;
    PPATTERN_U StructuredPattern = CreatePattern(pattern);
    ParsePattern(StructuredPattern);
    PSUB_PATTERN current = StructuredPattern->SubPatterns->next;
    const char* MatchStart = source; // 匹配到的子串的开始位置
    const char* SourceEnd = source + strlen(source);  // 整个字符串的结束位置
    int iMatchedLen; // 匹配到的长度
    bool NotMatched = false;
    const char* MatchEnd = MatchStart; // 某次匹配结束的位置
    while (MatchStart != SourceEnd)
    {
        while (current != NULL && MatchEnd != SourceEnd)
        {
            switch (current->mode)
            {
            case match_mode_t::ONCE:
                // 普通匹配一次
                if (MatchEnd != SourceEnd && !NotMatched)
                {
                    for (iMatchedLen = 0; iMatchedLen < current->SubLen; iMatchedLen++)
                    {
                        if (current->SubStart[iMatchedLen] == '.')
                        {
                            continue;
                        }
                        else
                        {
                            if (current->SubStart[iMatchedLen] != MatchEnd[iMatchedLen])
                            {
                                NotMatched = true;
                                break;
                            }
                        }
                    }
                    MatchEnd += iMatchedLen;
                }
                break;
            case match_mode_t::ONE_OR_MORE:
                if (MatchEnd != SourceEnd && !NotMatched)
                {
                    iMatchedLen = 0;
                    char* buffer;
                    PMATCH_RESULT SubResult;
                    const char* FirstStart;
                    if (current->SubLen == 1 && *current->SubStart == '.')
                    {
                        // 有通配符的匹配，其匹配长度与后一个子pattern有关
                        PSUB_PATTERN tmp = current->next;
                        if (tmp == NULL)
                        {
                            // 后面无子pattern，此时匹配应该结束了，因为通配符一直匹配到整个字符串的结尾
                            MatchEnd = SourceEnd;
                            break;
                        }
                        // 后面有子pattern，确定后面的子pattern第一次匹配到的位置
                        buffer = (char*)malloc(tmp->SubLen + 1);
                        strncpy_s(buffer, tmp->SubLen + 1, tmp->SubStart, tmp->SubLen);
                        SubResult = RegexMatch(MatchEnd, buffer);
                        free(buffer);
                        if (SubResult->iMatchedNum == 0)
                        {
                            // 后面的子pattern没有匹配到
                            FirstStart = MatchEnd;
                        }
                        else
                        {
                            // 确定后面一个子pattern第一次出现的位置
                            FirstStart = SubResult->pieces->next->position;
                        }
                        if (FirstStart == MatchEnd)
                        {
                            // 因为是一或多次，后面的子pattern没有匹配到或者是自己没有匹配的位置，这次的整个匹配都是失败的
                            NotMatched = true;
                        }
                        iMatchedLen = FirstStart - MatchEnd;
                    }
                    else
                    {
                        // 没有通配符的匹配
                        buffer = (char*)malloc(current->SubLen + 1);
                        strncpy_s(buffer, current->SubLen + 1, current->SubStart, current->SubLen);
                        SubResult = RegexMatch(MatchEnd, buffer);
                        free(buffer);
                        if (SubResult->iMatchedNum == 0)
                        {
                            // 没有匹配到
                            NotMatched = true;
                        }
                        else
                        {
                            PMATCH_PIECE piece = SubResult->pieces->next; // 第一条记录
                            FirstStart = piece->position;
                            if (FirstStart != MatchEnd)
                            {
                                // 匹配到但不是在原位置的
                                NotMatched = true;
                            }
                            else
                            {
                                // 匹配到且是正确位置
                                const char* LastEnd = FirstStart;
                                for (int i = 0; i < SubResult->iMatchedNum; i++)
                                {
                                    if (piece->position == LastEnd)
                                    {
                                        // 如果连续，匹配长度就是有效的
                                        iMatchedLen += piece->length;
                                        LastEnd = piece->position + piece->length;
                                        piece = piece->next;
                                    }
                                    else
                                    {
                                        // 不连续，本子pattern的匹配结束
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    // 更新本次匹配结束的位置，不管有没有匹配到
                    MatchEnd += iMatchedLen;
                    DestroyResult(&SubResult);
                }
                break;
            case match_mode_t::ZERO_OR_MORE:
                if (MatchEnd != SourceEnd && !NotMatched)
                {
                    iMatchedLen = 0;
                    char* buffer;
                    PMATCH_RESULT SubResult;
                    const char* FirstStart;
                    if (current->SubLen == 1 && *current->SubStart == '.')
                    {
                        // 有通配符的匹配，其匹配长度与后一个子pattern有关
                        PSUB_PATTERN tmp = current->next;
                        if (tmp == NULL)
                        {
                            // 后面无子pattern，此时匹配应该结束了，因为通配符一直匹配到整个字符串的结尾
                            MatchEnd = SourceEnd;
                            break;
                        }
                        // 后面有子pattern，确定后面的子pattern第一次匹配到的位置
                        buffer = (char*)malloc(tmp->SubLen + 1);
                        strncpy_s(buffer, tmp->SubLen + 1, tmp->SubStart, tmp->SubLen);
                        SubResult = RegexMatch(MatchEnd, buffer);
                        free(buffer);
                        if (SubResult->iMatchedNum == 0)
                        {
                            // 后面的子pattern没有匹配到，那么这一次整个没有匹配到
                            NotMatched = true;
                            FirstStart = MatchEnd;
                        }
                        else
                        {
                            // 确定后面一个子pattern第一次出现的位置
                            FirstStart = SubResult->pieces->next->position;
                        }
                        iMatchedLen = FirstStart - MatchEnd;
                    }
                    else
                    {
                        // 没有通配符的匹配
                        buffer = (char*)malloc(current->SubLen + 1);
                        strncpy_s(buffer, current->SubLen + 1, current->SubStart, current->SubLen);
                        SubResult = RegexMatch(MatchEnd, buffer);
                        free(buffer);
                        if (SubResult->iMatchedNum != 0)
                        {
                            PMATCH_PIECE piece = SubResult->pieces->next; // 第一条记录
                            FirstStart = piece->position;
                            if (FirstStart == MatchEnd)
                            {
                                // 匹配到且是正确位置
                                const char* LastEnd = FirstStart;
                                for (int i = 0; i < SubResult->iMatchedNum; i++)
                                {
                                    if (piece->position == LastEnd)
                                    {
                                        // 如果连续，匹配长度就是有效的
                                        iMatchedLen += piece->length;
                                        LastEnd = piece->position + piece->length;
                                        piece = piece->next;
                                    }
                                    else
                                    {
                                        // 不连续，本子pattern的匹配结束
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    // 更新本次匹配结束的位置，不管有没有匹配到
                    MatchEnd += iMatchedLen;
                    DestroyResult(&SubResult);
                }
                break;
            case match_mode_t::ONE_OR_NOT:
                if (MatchEnd != SourceEnd && !NotMatched)
                {
                    iMatchedLen = 0;
                    char* buffer;
                    PMATCH_RESULT SubResult;
                    const char* FirstStart;
                    if (current->SubLen == 1 && *current->SubStart == '.')
                    {
                        // 有通配符的匹配，其匹配长度与后一个子pattern有关
                        iMatchedLen = 1; // 默认匹配一个
                        PSUB_PATTERN tmp = current->next;
                        if (tmp != NULL)
                        {
                            // 后面无子pattern，通配符匹配一个字符。后面有子pattern，确定后面的子pattern第一次匹配到的位置
                            buffer = (char*)malloc(tmp->SubLen + 1);
                            strncpy_s(buffer, tmp->SubLen + 1, tmp->SubStart, tmp->SubLen);
                            SubResult = RegexMatch(MatchEnd, buffer);
                            free(buffer);
                            if (SubResult->iMatchedNum == 0)
                            {
                                // 后面的子pattern没有匹配到，那么这一个子pattern匹配一个，但是这一次整个没有匹配到
                                NotMatched = true;
                            }
                            else
                            {
                                // 确定后面一个子pattern第一次出现的位置
                                FirstStart = SubResult->pieces->next->position;
                                if (FirstStart == MatchEnd)
                                {
                                    iMatchedLen = 0;
                                }
                                else if (FirstStart != MatchEnd + 1)
                                {
                                    // 本次匹配到一个，但是整个匹配失败了
                                    NotMatched = true;
                                }
                            }
                        }
                    }
                    else
                    {
                        // 没有通配符的匹配
                        buffer = (char*)malloc(current->SubLen + 1);
                        strncpy_s(buffer, current->SubLen + 1, current->SubStart, current->SubLen);
                        SubResult = RegexMatch(MatchEnd, buffer);
                        free(buffer);
                        if (SubResult->iMatchedNum != 0)
                        {
                            PMATCH_PIECE piece = SubResult->pieces->next; // 第一条记录
                            FirstStart = piece->position;
                            if (FirstStart == MatchEnd)
                            {
                                // 匹配到且是正确位置
                                iMatchedLen = piece->length;
                            }
                        }
                    }
                    // 更新本次匹配结束的位置，不管有没有匹配到
                    MatchEnd += iMatchedLen;
                    DestroyResult(&SubResult);
                }
                break;
            default:
                break;
            }
            if (NotMatched)
            {
                // 没有匹配到
                NotMatched = false;
                MatchEnd = ++MatchStart;
                current = StructuredPattern->SubPatterns->next; // 从第一个pattern开始匹配
            }
            else
            {
                current = current->next;
            }
        }
        if (current != NULL)
        {
            // 说明刚刚的没有匹配到，整个就不会再匹配到了，因为上面的匹配只会在搜索完整个字符串的时候退出循环
            break;
        }
        else
        {
            NewPiece = (PMATCH_PIECE)malloc(sizeof(MATCH_PIECE));
            if (NewPiece == NULL)
            {
                fprintf(stderr, "Out of memory!\n");
                exit(EXIT_FAILURE);
            }
            NewPiece->position = MatchStart;
            NewPiece->length = MatchEnd - MatchStart;
            NewPiece->next = tail->next;
            tail->next = NewPiece;
            tail = NewPiece;
            result->iMatchedNum++;
            current = StructuredPattern->SubPatterns->next;
        }
        MatchStart = MatchEnd;
    }
    DestroyPattern(&StructuredPattern);
    return result;
}

PPATTERN_U CreatePattern(const char* raw)
{
    PPATTERN_U result = (PPATTERN_U)malloc(sizeof(PATTERN_U));
    if (result == NULL)
    {
        fprintf(stderr, "Out of Memory!");
        exit(EXIT_FAILURE);
    }
    result->raw = raw;
    result->SubPatterns = (PSUB_PATTERN)malloc(sizeof(SUB_PATTERN));
    if (result->SubPatterns == NULL)
    {
        fprintf(stderr, "Out of Memory!");
        free(result);
        exit(EXIT_FAILURE);
    }
    result->SubPatterns->next = NULL;
    return result;
}

PMATCH_RESULT CreateResult()
{
    PMATCH_RESULT result = (PMATCH_RESULT)malloc(sizeof(MATCH_RESULT));
    if (result == NULL)
    {
        fprintf(stderr, "Out of Memory!");
        exit(EXIT_FAILURE);
    }
    result->iMatchedNum = 0;
    result->pieces = (PMATCH_PIECE)malloc(sizeof(MATCH_PIECE));
    if (result->pieces == NULL)
    {
        fprintf(stderr, "Out of memory!\n");
        free(result);
        exit(EXIT_FAILURE);
    }
    result->pieces->next = NULL;
    return result;
}

void DestroyPattern(PPATTERN_U* pattern)
{
    if (*pattern == NULL)
    {
        return;
    }
    PSUB_PATTERN tmp;
    while ((*pattern)->SubPatterns != NULL)
    {
        tmp = (*pattern)->SubPatterns;
        (*pattern)->SubPatterns = tmp->next;
        free(tmp);
    }
    free(*pattern);
    *pattern = NULL;
}

void DestroyResult(PMATCH_RESULT* result)
{
    if (*result == NULL)
    {
        return;
    }
    PMATCH_PIECE tmp;
    while ((*result)->pieces != NULL)
    {
        tmp = (*result)->pieces;
        (*result)->pieces = tmp->next;
        free(tmp);
    }
    free(*result);
    *result = NULL;
    
}

void ParsePattern(PPATTERN_U pattern)
{
    int cursor = 0;
    int length = strlen(pattern->raw);
    const char* end = pattern->raw + length;
    PSUB_PATTERN tail = pattern->SubPatterns, current;
    current = (PSUB_PATTERN)malloc(sizeof(SUB_PATTERN));
    if (current == NULL)
    {
        fprintf(stderr, "Out of memory!\n");
        return;
    }
    current->SubStart = pattern->raw;
    current->SubLen = 0;
    const char* NewStart;
    while (current->SubStart != end)
    {
        if (*current->SubStart == '(')
        {
            // 该子pattern是一个表达式
            current->SubStart++;
            while (current->SubStart[current->SubLen] != ')')
            {
                current->SubLen++;
            }
            switch (current->SubStart[current->SubLen + 1])
            {
            case '*':
                current->mode = match_mode_t::ZERO_OR_MORE; // 0或多次
                break;
            case '+':
                current->mode = match_mode_t::ONE_OR_MORE; // 1或多次
                break;
            case '?':
                current->mode = match_mode_t::ONE_OR_NOT; // 0或1次
                break;
            default:
                break;
            }
            NewStart = current->SubStart + current->SubLen + 2;
        }
        else
        {
            // 该子pattern是一个普通的字符串
            while (current->SubStart + current->SubLen != end && current->SubStart[current->SubLen] != '(')
            {
                current->SubLen++;
            }
            current->mode = match_mode_t::ONCE;
            NewStart = current->SubStart + current->SubLen;
        }
        // 在尾部插入
        current->next = tail->next;
        tail->next = current;
        tail = current;
        current = (PSUB_PATTERN)malloc(sizeof(SUB_PATTERN));
        if (current == NULL)
        {
            fprintf(stderr, "Out of memory!\n");
            return;
        }
        current->SubStart = NewStart;
        current->SubLen = 0;
    }
    free(current);
}

const char* GetCourseSummary(cJSON* DataPiece, const char* start)
{
    const char* MatchEnd = start;
    char pattern[] = "<div class=\"category-title f-f0\">\n<span class=\"category-title_icon f-ib f-vam u-icon-categories\"></span>\n<span class=\"f-ib f-vam\">(.)*</span>\n</div>\n<div class=\"category-content j-cover-overflow\">\n<div class=\"f-richEditorText\">(.)+</div>\n</div>";
    PMATCH_RESULT result = RegexMatch(start, pattern);
    if (result->iMatchedNum != 0)
    {
        sprintf_s(pattern, strlen(pattern) + 1, "<div class=\"f-richEditorText\">(.)+</div>");
        PMATCH_RESULT tmp = RegexMatch(result->pieces->next->position, pattern);
        if (tmp->iMatchedNum != 0)
        {
            strncpy_s(TextBuffer, MAX_BUF_SIZE, tmp->pieces->next->position + 30, tmp->pieces->next->length - 36);
            cJSON_AddStringToObject(DataPiece, "courseSummary", TextBuffer);
            MatchEnd = tmp->pieces->next->position + tmp->pieces->next->length;
        }
        DestroyResult(&tmp);
    }
    DestroyResult(&result);
    return MatchEnd;
}

const char* GetCourseTarget(cJSON* DataPiece, const char* start)
{
    const char* MatchEnd = start;
    char pattern[] = "<div class=\"category-title f-f0\">\n<span class=\"category-title_icon f-ib f-vam u-icon-scholar\"></span>\n<span class=\"f-ib f-vam\">(.)+</span>\n</div>\n<div class=\"category-content j-cover-overflow\">\n<div class=\"f-richEditorText\">(.)+</div>\n</div>";
    PMATCH_RESULT result = RegexMatch(start, pattern);
    if (result->iMatchedNum != 0)
    {
        sprintf_s(pattern, strlen(pattern) + 1, "<div class=\"f-richEditorText\">(.)+</div>");
        PMATCH_RESULT tmp = RegexMatch(result->pieces->next->position, pattern);
        if (tmp->iMatchedNum != 0)
        {
            strncpy_s(TextBuffer, MAX_BUF_SIZE, tmp->pieces->next->position + 30, tmp->pieces->next->length - 36);
            cJSON_AddStringToObject(DataPiece, "courseTarget", TextBuffer);
            MatchEnd = tmp->pieces->next->position + tmp->pieces->next->length;
        }
        DestroyResult(&tmp);
    }
    DestroyResult(&result);
    return MatchEnd;
}

const char* GetCourseOutline(cJSON* DataPiece, const char* start)
{
    const char* MatchEnd = start;
    char pattern[] = "outLineDto: {\noutLine: \"(.)*\",(.)*outLineStructureDtos: [(.)*]\n}";
    PMATCH_RESULT result = RegexMatch(start, pattern);
    if (result->iMatchedNum != 0)
    {

        strncpy_s(TextBuffer, MAX_BUF_SIZE, result->pieces->next->position + 15, result->pieces->next->length - 18);
        cJSON_AddStringToObject(DataPiece, "courseOutline", TextBuffer);
        MatchEnd = result->pieces->next->position + result->pieces->next->length;
    }
    DestroyResult(&result);
    return MatchEnd;
}

const char* GetCourseReference(cJSON* DataPiece, const char* start)
{
    const char* MatchEnd = start;
    char pattern[] = "<div class=\"category-title f-f0\">\n<span class=\"category-title_icon f-ib f-vam f-18 u-icon-stacks\"></span>\n<span class=\"f-ib f-vam\">(.)+</span>\n</div>\n<div class=\"category-content j-cover-overflow\">\n<div class=\"f-richEditorText\">(.)+</div>\n</div>";
    PMATCH_RESULT result = RegexMatch(start, pattern);
    if (result->iMatchedNum != 0)
    {
        sprintf_s(pattern, strlen(pattern) + 1, "<div class=\"f-richEditorText\">(.)+</div>");
        PMATCH_RESULT tmp = RegexMatch(result->pieces->next->position, pattern);
        if (tmp->iMatchedNum != 0)
        {
            strncpy_s(TextBuffer, MAX_BUF_SIZE, tmp->pieces->next->position + 30, tmp->pieces->next->length - 36);
            cJSON_AddStringToObject(DataPiece, "courseReference", TextBuffer);
            MatchEnd = tmp->pieces->next->position + tmp->pieces->next->length;
        }
        DestroyResult(&tmp);
    }
    DestroyResult(&result);
    return MatchEnd;
}


