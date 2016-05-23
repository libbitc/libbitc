#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <ccoin/logging.h>




static char *log_level_names[]= {
  "FATAL",
  "ERROR",
  "WARNING",
};

int glog_level=LOG_WARNING;//log nothing by default
int guse_local_time= 1;// use  gmt by default

static inline void generate_time_str(char *buffer)
{

    extern int guse_local_time;

    const time_t _rt = time(0);
    struct tm _bdt;
    if (guse_local_time){
      localtime_r(&_rt, &_bdt);
    }
    else{
      gmtime_r(&_rt, &_bdt);
    }
    sprintf(buffer,"[%02d:%02d:%02d%6s-%02d/%02d/%04d]", _bdt.tm_hour, _bdt.tm_min, _bdt.tm_sec, _bdt.tm_zone, _bdt.tm_mday, (_bdt.tm_mon+1), _bdt.tm_year+1900);
}

void enter_function_log(const char *function_name)
{

    extern int glog_level;

    if (!glog_level){
       return;
    }

    char buffer[256];
    generate_time_str(buffer);

    printf ("%s, Enter function:[%s]\n",buffer, function_name);
}


void leave_function_log(const char *function_name)
{

    extern int glog_level;

    if (!glog_level){
       return;
    }

    char buffer[256];
    generate_time_str(buffer);

    printf("%s, Leaving function:[%s]\n", buffer, function_name);

}

void log_messagef(const char *function_name, const int line, const int log_level, const char *format, ...)
{

  	extern int glog_level;
	if (glog_level < log_level && log_level != LOG_NOTIFY){
        	return;
	}

    char buffer[256];

    va_list args;
	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);

        log_message(function_name, line, log_level, buffer);
}

void log_message(const char *function_name, const int line, const int log_level, const char *log_message)
{
    //
    extern int glog_level;

    if (glog_level < log_level && log_level != LOG_NOTIFY){
        return;
    }

    char buffer[256];
    generate_time_str(buffer);

    char *ptr = buffer+strlen(buffer);// remove zero-term, with overwrite

    sprintf(ptr, "[%s][:%d], ", function_name, line);

    ptr = ptr+strlen(ptr);// remove zero-term, with overwrite

    switch(log_level){

    case LOG_WARNING:
        sprintf(ptr," [%s] ",log_level_names[LOG_WARNING-LOG_OFFSET]);
        break;
    case LOG_ERROR:
        sprintf(ptr," [%s] ",log_level_names[LOG_ERROR-LOG_OFFSET]);
        break;
    case LOG_FATAL:
        sprintf(ptr," [%s] ",log_level_names[LOG_FATAL-LOG_OFFSET]);
        break;
    default:
        break;
    }

    ptr = ptr+strlen(ptr);// remove zero-term, with overwrite

    sprintf(ptr, "%s", log_message);

    printf("%s\n", buffer);

}


