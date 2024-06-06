#define _GNU_SOURCE

#if defined(__x86_64__) || defined(__i386__)
#define ARCH_X86_64
#elif defined(__aarch64__)
#define ARCH_ARM64
#endif

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <omp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef ARCH_ARM64
#include <linux/elf.h>
#include <linux/ptrace.h>
#include <sys/uio.h>
#endif

// Define an enum with types of memory
typedef enum { HEAP_MEMORY, STACK_MEMORY, DATA_MEMORY } MemoryType;
typedef enum {
  PLACE_APP,
  PLACE_RUNTIME,
  PLACE_UNKNOWN,
  PLACE_MIX,
  PLACE_NONE
} PlaceType;

const char *getMemoryTypeName(MemoryType type) {
  switch (type) {
  case HEAP_MEMORY:
    return "HEAP_MEMORY";
  case STACK_MEMORY:
    return "STACK_MEMORY";
  case DATA_MEMORY:
    return "DATA_MEMORY";
  default:
    return "UNKNOWN_MEMORY_TYPE";
  }
}
const char *getPlaceTypeName(PlaceType type) {
  switch (type) {
  case PLACE_APP:
    return "PLACE_APP";
  case PLACE_RUNTIME:
    return "PLACE_RUNTIME";
  case PLACE_UNKNOWN:
    return "PLACE_UNKNOWN";
  case PLACE_MIX:
    return "PLACE_MIX";
  case PLACE_NONE:
    return "PLACE_NONE";
  default:
    return "Invalid PlaceType";
  }
}

typedef struct AllocNode {
  void *address;
  size_t size;
  struct AllocNode *next;
  MemoryType type;
  PlaceType place;
} AllocNode;

static AllocNode *head = NULL;

// Original function pointers
void *(*real_malloc)(size_t) = NULL;
void (*real_free)(void *) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;

void initialize();
// Initialize real_malloc and real_free
__attribute__((constructor)) void init() {
  real_malloc = dlsym(RTLD_NEXT, "malloc");
  if (!real_malloc) {
    fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
  }

  real_free = dlsym(RTLD_NEXT, "free");
  if (!real_free) {
    fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
  }

  real_realloc = dlsym(RTLD_NEXT, "realloc");
  if (!real_realloc) {
    fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
  }
  initialize();
}

// Function to get the total size of all nodes in the list
size_t get_total_size(int mem_heap) {
  size_t total_size = 0;
  AllocNode *current = head;
  while (current != NULL) {
    if (mem_heap == 0 && current->type == HEAP_MEMORY) {
      current = current->next;
      continue;
    }
    total_size += current->size;
    current = current->next;
  }

  return total_size;
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// Function to add a node to the linked list
void add_alloc_node(void *addr, size_t size, int type, int place) {
  AllocNode *new_node = (AllocNode *)real_malloc(sizeof(AllocNode));
  if (new_node == NULL) {
    fprintf(stderr, "Error allocating memory for new node\n");
    return;
  }
  new_node->address = addr;
  new_node->size = size;
  new_node->type = type;
  new_node->next = head;
  new_node->place = place;
  head = new_node;
}
// Custom malloc
void *malloc(size_t size) {
  if (real_malloc == NULL) {
    init();
  }
  void *ptr = real_malloc(size);
  if (ptr) {
    pthread_mutex_lock(&lock);
    add_alloc_node(ptr, size, HEAP_MEMORY, PLACE_RUNTIME);
    pthread_mutex_unlock(&lock);
  }
  return ptr;
}
// Custom malloc
void *app_malloc(size_t size) {
  if (real_malloc == NULL) {
    init();
  }
  void *ptr = real_malloc(size);
  if (ptr) {
    pthread_mutex_lock(&lock);
    add_alloc_node(ptr, size, HEAP_MEMORY, PLACE_APP);
    pthread_mutex_unlock(&lock);
  }
  return ptr;
}

// Custom free
void free(void *ptr) {
  if (real_free == NULL) {
    init();
  }

  if (ptr) {
    pthread_mutex_lock(&lock);
    AllocNode **curr = &head;
    while (*curr) {
      AllocNode *entry = *curr;
      if (entry->address == ptr) {
        *curr = entry->next;
        real_free(entry);
        break;
      }
      curr = &(*curr)->next;
    }
    pthread_mutex_unlock(&lock);
  }
  real_free(ptr);
}

void *realloc(void *ptr, size_t size) {
  if (!real_realloc) {
    init();
  }

  pthread_mutex_lock(&lock);
  AllocNode *node = NULL;
  if (ptr != NULL) {
    AllocNode **curr = &head;
    while (*curr) {
      AllocNode *entry = *curr;
      if (entry->address == ptr) {
        node = entry;
        break;
      }
      curr = &(*curr)->next;
    }
  }

  void *new_ptr = real_realloc(ptr, size);
  if (new_ptr && node) {
    if (new_ptr != ptr) {
      // Update the node with new address if it changes
      node->address = new_ptr;
    }
    node->size = size; // Update the size
  } else if (!new_ptr && size != 0) {
    // Realloc failed and it was not a free operation
    fprintf(stderr, "Failed to reallocate memory\n");
  }
  pthread_mutex_unlock(&lock);

  return new_ptr;
}
unsigned long data_section_start = 0;

void parse_address_size_file(const char *filename) {
  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    perror("Unable to open the obj file. Errors will not be inserted in global "
           "variables");
    return;
  }

  unsigned long addr, sz;
  size_t total_size = 0;
  while (fscanf(file, "%lx %lx", &addr, &sz) == 2) {
    if (sz == 0) { // Skip this pair if the size is zero
      continue;
    }
    total_size += sz;
    add_alloc_node((void *)addr + data_section_start, sz, DATA_MEMORY,
                   PLACE_APP);
  }
  fclose(file);
}

// Helper function to parse hexadecimal addresses
unsigned long parse_hex_address(const char *address) {
  unsigned long addr;
  sscanf(address, "%lx", &addr);
  return addr;
}

void add_stack_info(int pid, unsigned long sp) {
  char filename[256];
  FILE *fp;
  char line[1024];
  char *start_addr_str, *end_addr_str;
  unsigned long start_addr, end_addr;

  // Construct the path to the maps file for the thread
  snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
  fp = fopen(filename, "r");
  if (!fp) {
    fprintf(stderr, "Failed to open maps file: %s\n", strerror(errno));
    return;
  }
  // Read memory mappings to find the stack segment
  while (fgets(line, sizeof(line), fp)) {
    // Parse the start and end addresses from the line
    start_addr_str = strtok(line, "-");
    end_addr_str = strtok(NULL, " ");
    start_addr = parse_hex_address(start_addr_str);
    end_addr = parse_hex_address(end_addr_str);

    // Check if the stack pointer falls within this range
    if (sp >= start_addr && sp < end_addr) {
      unsigned long stack_used = end_addr - sp;
      unsigned long stack_total = end_addr - start_addr;
      add_alloc_node((void *)sp, stack_used, STACK_MEMORY, PLACE_MIX);
      break;
    }
  }
  // Reset the file pointer to the start to search for the data section
  fseek(fp, 0, SEEK_SET);

  // Scan for the data section which is usually not labeled but has 'rw-p'
  // permissions
  unsigned long stack_top;
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, " r--p") && !strstr(line, "[heap]") &&
        !strstr(line, "[stack]")) {
      sscanf(line, "%lx-%lx", &data_section_start, &stack_top);
      // printf("Data section start: 0x%lx  0x%lx\n", data_section_start,
      //        stack_top);
      break;
    }
  }
  fclose(fp);
}

// Function to return a random thread ID from a given PID, excluding the
// caller's TID
int get_random_thread_id(int pid) {
  DIR *dir;
  struct dirent *entry;
  char path[256];
  int tids[256]; // Adjust size as needed, assuming a maximum of 256 threads for
                 // simplicity
  int count = 0;
  pid_t mypid = syscall(SYS_gettid);

  // Construct the path to /proc/[pid]/task
  snprintf(path, sizeof(path), "/proc/%d/task", pid);

  // Open the directory
  dir = opendir(path);
  if (dir == NULL) {
    fprintf(stderr, "Failed to open directory %s: %s\n", path, strerror(errno));
    return -1; // Return error
  }

  // Read the thread IDs, excluding mypid
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 &&
        strcmp(entry->d_name, "..") != 0) {
      int tid = atoi(entry->d_name);
      if (tid != mypid) {
        tids[count++] = tid;
      }
    }
  }

  closedir(dir);

  if (count == 0) {
    return -1; // No valid thread ID found
  }

  // Select a random thread ID from the list
  int random_index = rand() % count;
  return tids[random_index];
}

void performBitFlipInRandomRegister(pid_t pid, unsigned long current_rsp,
                                    PlaceType *place) {
#ifdef ARCH_X86_64
  struct user_regs_struct regs;
  const int num_registers = 16;
  char *register_names[] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                            "rbp", "rsp", "r8",  "r9",  "r10", "r11",
                            "r12", "r13", "r14", "r15"};
#elif defined(ARCH_ARM64)
  struct user_pt_regs regs;
  struct iovec io;
  io.iov_base = &regs;
  io.iov_len = sizeof(regs);
  const int num_registers = 33;
  char *register_names[] = {"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",
                            "x7",  "x8",  "x9",  "x10", "x11", "x12", "x13",
                            "x14", "x15", "x16", "x17", "x18", "x19", "x20",
                            "x21", "x22", "x23", "x24", "x25", "x26", "x27",
                            "x28", "x29", "x30", "x31"};
#endif

#ifdef ARCH_X86_64
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
#elif defined(ARCH_ARM64)
  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io) == -1) {
#endif
    perror("Failed to get registers");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return;
  }

  unsigned long long *registers[num_registers];
#ifdef ARCH_X86_64
  unsigned long long *registers_x86_64[] = {
      &regs.rax, &regs.rbx, &regs.rcx, &regs.rdx, &regs.rsi, &regs.rdi,
      &regs.rbp, &regs.rsp, &regs.r8,  &regs.r9,  &regs.r10, &regs.r11,
      &regs.r12, &regs.r13, &regs.r14, &regs.r15,
  };
  memcpy(registers, registers_x86_64, sizeof(registers_x86_64));
#elif defined(ARCH_ARM64)
  registers[0] = &regs.sp;
  for (int i = 1; i < num_registers; i++) {
    registers[i] = &regs.regs[i - 1];
  }
#endif

  const char *env = getenv("REGISTERS");
  int indices[num_registers];
  int valid_count = 0;

  if (env && strlen(env) > 0) {
    char *env_copy = strdup(env);
    char *token = strtok(env_copy, ",");
    while (token) {
      for (int i = 0; i < num_registers; i++) {
        if (strcmp(token, register_names[i]) == 0) {
          indices[valid_count++] = i;
          break;
        }
      }
      token = strtok(NULL, ",");
    }
    free(env_copy);
  }

  // If no valid registers are found in the environment, consider all registers
  if (valid_count == 0) {
    for (int i = 0; i < num_registers; i++) {
      indices[i] = i;
    }
    valid_count = num_registers;
  }

  // Choose a random register from the filtered list and flip a random bit
  srand(time(NULL)); // Seed the random number generator
  int reg_index = indices[rand() % valid_count];
  unsigned long long *selected_reg = registers[reg_index];
  int bit_position = rand() % (sizeof(unsigned long long) * 8);
  *selected_reg ^= (1UL << bit_position);
  printf("Flipped bit %d in register %s\n", bit_position,
         register_names[reg_index]);

  // Update registers
#ifdef ARCH_X86_64
  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
#elif defined(ARCH_ARM64)
  if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &io) == -1) {
#endif
    perror("Failed to set registers");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
  }
}

void performBitFlipInMemory(int bytePosition, pid_t pid, PlaceType *place,
                            int mem_heap) {
  srand((unsigned int)time(NULL));
  bytePosition = rand() % (bytePosition);
  AllocNode *current = head;
  size_t totalSize = 0;
  void *targetAddress = NULL;

  // Traverse the linked list to find the node containing the byte position
  while (current != NULL) {
    if (mem_heap == 0 && current->type == HEAP_MEMORY) {
      current = current->next;
      continue;
    }

    if (totalSize + current->size > bytePosition) {
      // Found the node containing the byte
      size_t offset = bytePosition - totalSize;
      targetAddress = (char *)current->address + offset;

      printf("Bit flipped in address %p in region %s of %ld bytes\n",
             targetAddress, getMemoryTypeName(current->type), current->size);
      long data = ptrace(PTRACE_PEEKDATA, pid, (void *)targetAddress, NULL);
      if (errno) {
        perror("PTRACE_PEEKDATA");
        return;
      }
      // Flip a random bit in the data
      int bit = rand() % 8; // restrict bit flipping to the first byte
      data ^= (1L << bit);  // shift the bit within the bounds of the first byte

      if (ptrace(PTRACE_POKEDATA, pid, (void *)targetAddress, (void *)data) ==
          -1) {
        perror("PTRACE_POKEDATA");
        return;
      }
      return;
    }
    totalSize += current->size;
    current = current->next;
  }

  printf("Byte position %d is out of the bounds of the linked list.\n",
         bytePosition);
}

pid_t new_process;
int is_child = 0;
void fork_and_inject() {
#ifdef ARCH_X86_64
  struct user_regs_struct regs;
#elif defined(ARCH_ARM64)
  struct user_pt_regs regs;
  struct iovec io;
  io.iov_base = &regs;
  io.iov_len = sizeof(regs);
#endif
  pid_t target_pid = get_random_thread_id(getpid());
  pid_t pid = fork();
  if (pid == -1) {
    perror("Failed to fork");
    return;
  }
  if (pid == 0) {
    is_child = 1;
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
      perror("ptrace attach");
      return;
    }

    waitpid(target_pid, NULL, 0);

#ifdef ARCH_X86_64
    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == -1) {
#elif defined(ARCH_ARM64)
    if (ptrace(PTRACE_GETREGSET, target_pid, NT_PRSTATUS, &io) == -1) {
#endif
      perror("ptrace getregs");
      ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
      return;
    }
    unsigned long current_rsp;
#ifdef ARCH_X86_64
    current_rsp = regs.rsp;
#elif defined(ARCH_ARM64)
    current_rsp = regs.sp;
#endif
    int mem_data = 1;
    int mem_stack = 1;
    int mem_heap = 1;

    const char *memoryRegion = getenv("MEMORY_REGIONS");
    if (memoryRegion != NULL) {
      if (strcmp(memoryRegion, "DATA") == 0) {
        // Handle memory operations specific to the DATA region
        mem_stack = 0;
        mem_heap = 0;
      } else if (strcmp(memoryRegion, "HEAP") == 0) {
        // Handle memory operations specific to the HEAP region
        mem_data = 0;
        mem_stack = 0;
      } else if (strcmp(memoryRegion, "STACK") == 0) {
        // Handle memory operations specific to the STACK region
        mem_data = 0;
        mem_heap = 0;
      }
    }

    const char *numBitflipsStr = getenv("NUM_BITFLIPS");
    int numBitflips = 1; // Default to 1 if not set or invalid

    if (numBitflipsStr != NULL) {
      numBitflips = atoi(numBitflipsStr); // Convert string to integer
    }
    const char *mode = getenv("MODE");
    PlaceType placeInserted = PLACE_NONE;
    if (mode != NULL) {
      if (strcmp(mode, "REGISTER") == 0) {
        for (int i = 0; i < numBitflips; i++)
          performBitFlipInRandomRegister(target_pid, current_rsp,
                                         &placeInserted);
      } else if (strcmp(mode, "MEMORY") == 0) {
        if (mem_stack)
          add_stack_info(target_pid, current_rsp);
        if (mem_data)
          parse_address_size_file("object_file.txt");
        size_t total_size = get_total_size(mem_heap);
        for (int i = 0; i < numBitflips; i++)
          performBitFlipInMemory(total_size, target_pid, &placeInserted,
                                 mem_heap);
      } else if (strcmp(mode, "RANDOM") == 0) {
        if (rand() % 2) { // Generates a random number and checks if it is odd
                          // (50% chance)
          for (int i = 0; i < numBitflips; i++)
            performBitFlipInRandomRegister(target_pid, current_rsp,
                                           &placeInserted);
        } else {
          if (mem_stack)
            add_stack_info(target_pid, current_rsp);
          if (mem_data)
            parse_address_size_file("list.txt");
          size_t total_size = get_total_size(mem_heap);
          for (int i = 0; i < numBitflips; i++)
            performBitFlipInMemory(total_size, target_pid, &placeInserted,
                                   mem_heap);
        }
      } else {
        fprintf(stderr,
                "Invalid mode specified. Error will be injected randomly\n");
        exit(0);
      }
    } else {
      fprintf(stderr, "MODE environment variable is not set. Error will be "
                      "injected randomly\n");
    }
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    exit(0);
  } else {
    new_process = pid;
    waitpid(pid, NULL, 0); // Wait for the child to finish
  }
}

int sleep_random_delay_time() {
  // Get the DELAY_TIME environment variable
  char *delayStr = getenv("DELAY_TIME");
  if (delayStr == NULL) {
    printf("DELAY_TIME environment variable is not set. Error will not be "
           "inserted\n");
    return 0;
  }

  // Convert the delay from string to integer (maximum delay in milliseconds)
  int maxDelayMs = atoi(delayStr);
  if (maxDelayMs <= 0) {
    printf("Invalid DELAY_TIME value.\n");
    return 0;
  }

  // Seed the random number generator
  srand((unsigned)time(NULL));
  // Generate a random delay between 0 and maxDelayMs
  int randomDelayMs = rand() % (maxDelayMs + 1);

  // Set up the timespec structure for nanosleep
  struct timespec ts;
  ts.tv_sec = randomDelayMs / 1000; // Convert milliseconds to seconds
  ts.tv_nsec =
      (randomDelayMs % 1000) * 1000000; // Convert remainder to nanoseconds

  // Call nanosleep
  int ret = nanosleep(&ts, NULL);
  if (ret == -1) {
    perror("nanosleep");
    printf("sleep error \n");
    return 0;
  }
  return 1;
}

void *pthread_wrapper(void *arg) {
  srand((unsigned int)time(NULL));
  // Wait for a random amount of time between 0 and 1 seconds
  if (sleep_random_delay_time()) {
    fork_and_inject(); // Call your original function
  }
  return NULL; // Return NULL as required by the pthread signature
}
void initialize() {
  // Enable line-buffering to avoid duplication of standard output when forking
  setvbuf(stdout, NULL, _IOLBF, 0);
  pthread_t thread;
  int result = pthread_create(&thread, NULL, pthread_wrapper, NULL);
  if (result != 0) {
    perror("pthread_create");
    return;
  }
}

__attribute__((destructor)) void finalize() {
  if (!is_child) {
    // Check if the process exists and we have permission to send it a signal
    if (kill(new_process, 0) == 0) {
      // Process exists, send SIGINT
      if (kill(new_process, SIGINT) != 0) {
        perror("Failed to send SIGINT");
        return;
      }
    }
  }
}