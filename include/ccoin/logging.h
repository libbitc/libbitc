#ifndef _LOGGING_H_
#define _LOGGING_H_

extern int glog_level;
extern int guse_local_time;

void enter_function_log(const char *function_name);
void leave_function_log(const char *function_name);
void log_message(const char *function_name, const int line, const int log_level, const char *log_message);
void log_messagef(const char *function_name, const int line, const int log_level, const char *format, ...);

#define LOG_MSG(x,y) log_message(__func__, __LINE__, x , y )
#define LOG_MSG_ERR(y) LOG_MSG(LOG_ERROR, y)
#define LOG_MSG_WARN(y) LOG_MSG(LOG_WARNING, y)
#define LOG_MSG_FATAL(y) LOG_MSG(LOG_FATAL, y)
#define LOG_MSG_NOTIFY(y) LOG_MSG(LOG_NOTIFY,y)
#define LOG(x, ... ) log_messagef(__func__, __LINE__, LOG_NOTIFY, x, ##__VA_ARGS__ )
#define LOG_EXIT(x, y, ... ) log_messagef(__func__, __LINE__, LOG_FATAL, y, ##__VA_ARGS__ ); exit(x)
#define LOG_ERR_RC(x,y, ... ) log_messagef(__func__, __LINE__, LOG_ERROR, y, ##__VA_ARGS__); return x
#define LOG_ERR_EXIT(x,y, ... ) log_messagef(__func__, __LINE__, LOG_ERROR, y, ##__VA_ARGS__); exit(x)


#define LOG_INIT(x) glog_level = x
#define LOG_BEGIN enter_function_log(__func__)
#define LOG_END leave_function_log(__func__)
#define LOG_END_RC(x) LOG_END; return x

#define LOG_LOCAL_ZONE guse_local_time=1
#define LOG_GMT_ZONE guse_local_time=0

enum {
  LOG_NOTHING=0,
  LOG_NOTIFY=777,
  LOG_ALL=6,
  LOG_FINE=5,
  LOG_DEBUG=4,
  LOG_OFFSET=1,
  LOG_WARNING=3,
  LOG_ERROR=2,
  LOG_FATAL=1
};

#endif

