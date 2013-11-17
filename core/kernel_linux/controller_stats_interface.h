#ifndef __CONTROLLER_STATS_INTERFACE_H_
#define __CONTROLLER_STATS_INTERFACE_H_

#include <iostream>

extern void dump_kstats(char *buffer, unsigned long buffer_size,
                        std::ostream &out);

extern void dump_stats(char *buffer, unsigned long buffer_size,
                       std::ostream &out);

#endif
