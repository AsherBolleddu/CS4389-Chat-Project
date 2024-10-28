#ifndef LOGGER_H
#define LOGGER_H

void init_logger(const char *filename);
void log_info(const char *format, ...); 
void close_logger();

#endif // LOGGER_H
