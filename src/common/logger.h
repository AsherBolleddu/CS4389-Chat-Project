#ifndef LOGGER_H
#define LOGGER_H

void init_logger(const char* filename);
void log_info(const char* format, ...);
void log_info_cr(const char* format, ...);
void log_info_noline(const char* format, ...);
char* read_log_file(const char* filename);
void close_logger();

#endif // LOGGER_H
