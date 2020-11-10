/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Contributor(s):  Michael Abd-El-Malek (mabdelmalek@cmu.edu)
 *                  Carnegie Mellon University
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable
 * instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */



/*
 * This file contains routines for printing a stack trace of all threads.
 * Only works when DEBUG is defined and where glibc is available, since it
 * provides the backtrace() function.
 */

#define _GNU_SOURCE  /* to get program_invocation_name */

#include <stdio.h>
#include <stdlib.h>


#if defined(DEBUG) && defined(__GLIBC__)

#include <errno.h>
#include "common.h"
#include <execinfo.h>
#include <inttypes.h>
#include <string.h>


/* The maximum number of frames to get a stack trace for.  If a thread has more
 * frames than this, then we only show the latest X frames. */
#define MAX_NUM_FRAMES 64


typedef struct thread_stack_s {
   uint32_t        num_frames;
   void*           addresses[MAX_NUM_FRAMES]; /* frame pointers */
   char*           locations[MAX_NUM_FRAMES]; /* file/function/line numbers  */
   uint32_t        num_matches;

   struct thread_stack_s* next;
} thread_stack_t;

static thread_stack_t* stacks = NULL;


/* Converts the function's memory addresses to function names, file names, and
 * line numbers.  Calls binutil's addr2line program. */
static void get_symbol_names(thread_stack_t *stack)
{
     char program_to_run[1024], function[256], filename_lineno[256], temp[19];
     FILE* output;
     int num_bytes_left;
     uint32_t i;

     /* Construct the arguments to addr2line */
     num_bytes_left = sizeof(program_to_run);
     num_bytes_left -= snprintf(program_to_run, sizeof(program_to_run),
                                "addr2line -fCe %s", program_invocation_name);
     for (i = 0; i < stack->num_frames && num_bytes_left > 0; ++i) {
         num_bytes_left -= snprintf(temp, sizeof(temp), " %p", stack->addresses[i]);
         strncat(program_to_run, temp, num_bytes_left);
     }

     /* Use popen to execute addr2line and read its ouput */
     output = popen(program_to_run, "r");
     for (i = 0; i < stack->num_frames; ++i) {
         char* function_listing = (char*) malloc(512);
         fscanf(output, "%255s\n", function);
         fscanf(output, "%255s\n", filename_lineno);
         snprintf(function_listing, 512, "%s at %s", function, filename_lineno);
         stack->locations[i] = function_listing;
     }
     pclose(output);
}


static void print_stack(thread_stack_t* stack)
{
     int skip_offset = 0, cmp_len;
     uint32_t i;

     /* Get the function names/filenames/line numbers */
     get_symbol_names(stack);

     cmp_len = strlen("_st_iterate_threads_helper");

     /* Print the backtrace */
     for (i = 0; i < stack->num_frames; ++i) {
         /* Skip frames we don't have location info for */
         if (!strncmp(stack->locations[i], "??", 2)) {
             continue;
         }

         /* Skip the frames that are used for printing the stack trace */
         if (skip_offset) {
             printf("\t#%2d %s %p\n", i - skip_offset, stack->locations[i],
                    stack->addresses[i]);
         } else if (!strncmp(stack->locations[i], "_st_iterate_threads_helper",
                             cmp_len)) {
             skip_offset = i + 1;
         }
     }
}


static void add_current_thread_stack(void)
{
     thread_stack_t *new_stack = malloc(sizeof(thread_stack_t));
     thread_stack_t *search;

     /* Call glibc function to get the backtrace */
     new_stack->num_frames = backtrace(new_stack->addresses, MAX_NUM_FRAMES);

     /* Check if we have another stacks that is equivalent.  If so, then coaelsce
      *  two stacks into one, to minimize output to user. */
     search = stacks;
     while (search) {
         if (search->num_frames == new_stack->num_frames &&
             !memcmp(search->addresses, new_stack->addresses,
                     search->num_frames * sizeof(void*))) {
             /* Found an existing stack that is the same as this thread's stack */
             ++search->num_matches;
             free(new_stack);
             return;
         } else {
             search = search->next;
         }
     }

     /* This is a new stack.  Add it to the list of stacks. */
     new_stack->num_matches = 1;
     new_stack->next = stacks;
     stacks = new_stack;
}

static void print_stack_frames(void)
{
     while (stacks) {
         printf("\n%u thread(s) with this backtrace:\n", stacks->num_matches);
         print_stack(stacks);
         stacks = stacks->next;
     }
     printf("\n");
}

static void free_stacks(void)
{
     uint32_t i;
     while (stacks) {
         thread_stack_t *next = stacks->next;
         for (i = 0; i < stacks->num_frames; ++i) {
             free(stacks->locations[i]);
         }
         free(stacks);
         stacks = next;
     }
     stacks = NULL;
}


static void st_print_thread_stack(_st_thread_t *thread, int start_flag,
                                   int end_flag)
{
     if (end_flag == 0) {
         add_current_thread_stack();
     } else {
         print_stack_frames();
     }
}


void _st_print_thread_stacks(int ignore)
{
     _st_iterate_threads_flag = 1;
     _st_iterate_threads_helper(st_print_thread_stack);
     _st_iterate_threads_flag = 0;

     /* Deallocate memory */
     free_stacks();
}

#else  /* defined(DEBUG) && defined(__GLIBC__) */

void _st_print_thread_stacks(int ignore)
{
     printf("%s: need DEBUG mode and glibc-specific functions to read stack.\n",
            __FUNCTION__);
}
#endif /* defined(DEBUG) && defined(__GLIBC__) */
