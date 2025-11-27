#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 16

char* get_message() {
    char msg[20];
    strcpy(msg, "Hello World");
    return msg;
}

void print_len(char *s) {
    int len = strlen(s);
    printf("len=%d\n", len);
}

void copy_user(char *input) {
    char buf[8];
    strcpy(buf, input);
    printf("Copied: %s\n", buf);
}

void process_data(int count) {
    char *data = malloc(count);
    //potential out-of-bounds write
    for (int i = 0; i < count + 10; i++) {
        data[i] = 'A';
    }

    printf("done processing\n");
    free(data);
}

void test_double_free() {
    char *x = malloc(32);
    //double free
    free(x);
    free(x);
}

void uninitialized_usage() {
    char *p;
    printf("first char: %c\n", p[0]);
}

void read_input() {
    char name[16];
    printf("Enter name: ");
    //BOF
    gets(name);
    printf("Hello %s\n", name);
}

void realloc_bug() {
    char *buf = malloc(8);
    //
    strcpy(buf, "ABCDEFG");

    buf = realloc(buf, 6);
    strcat(buf, "XXX");
    printf("%s\n", buf);

    free(buf);
}

void use_after_free_simple() {
    char *p = malloc(16);
    strcpy(p, "hello");
    free(p);
    //UAF
    printf("%s\n", p);
}

void deep_copy(char *src) {
    char tmp[10];
    strcpy(tmp, src);
}

void deep() {
    char input[MAX_SIZE * 2];
    strcpy(input, "AAAAAAAAAAAAAAAAAAAAAA");
    deep_copy(input);
}

int main() {
    char *msg = get_message();
    printf("%s\n", msg);

    print_len(NULL);
    copy_user("THIS_IS_TOO_LONG!!!!");
    process_data(8);
    test_double_free();
    uninitialized_usage();
    read_input();
    realloc_bug();
    use_after_free_simple();
    deep();

    return 0;
}

