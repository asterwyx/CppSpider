#ifndef _REGEX_H
#define _REGEX_H
#include "cJSON.h"
#define MAX_RANGE		5
#define MAX_BUF_SIZE	1024*1024

typedef enum class MatchMode {
    ONCE,
    ZERO_OR_MORE,
    ONE_OR_MORE,
    ONE_OR_NOT
} MATCH_MODE;

typedef struct SubPattern {
    const char* SubStart;
    int SubLen;
    MATCH_MODE mode;
    struct SubPattern* next;
} SUB_PATTERN, * PSUB_PATTERN;

typedef struct Pattern {
    const char* raw;
    PSUB_PATTERN SubPatterns;
} PATTERN_U, * PPATTERN_U;

// 匹配的一个位置
typedef struct MatchPiece {
    const char* position;
    int length;
    struct MatchPiece* next;
} MATCH_PIECE, * PMATCH_PIECE;

// 匹配的全部结果
typedef struct MatchResult {
    int iMatchedNum;
    PMATCH_PIECE pieces;
} MATCH_RESULT, * PMATCH_RESULT;

PMATCH_RESULT RegexMatch(const char* source, const char* pattern);
PPATTERN_U CreatePattern(const char* raw);
PMATCH_RESULT CreateResult();
void DestroyPattern(PPATTERN_U* pattern);
void DestroyResult(PMATCH_RESULT* result);
void ParsePattern(PPATTERN_U pattern);
const char* GetCourseSummary(cJSON* DataPiece, const char* start);
const char* GetCourseTarget(cJSON* DataPiece, const char* start);
const char* GetCourseOutline(cJSON* DataPiece, const char* start);
const char* GetCourseReference(cJSON* DataPiece, const char* start);

#endif // !_REGEX_H
