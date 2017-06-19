#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "../lib/api.h"

const size_t kMaxOprs = 5;
char *oprs[kMaxOprs];
size_t op_cnt = 0;

const int kCommandBufSize = 1024;
char command_buf[kCommandBufSize];

void read_command();
int command_exit();
void execute_command();
int parse_args(int argc, char *argv[]);

sqrl_t *sqrl;
FILE *fScript;
FILE *fin;

int main(int argc, char *argv[])
{
    if(sqrl_init(&sqrl))
    {
        printf("Error initializing SQRL Core\n");
        return 1;
    }
    
    fin = stdin;
    sqrl_log(sqrl, stderr);
    parse_args(argc, argv);
    
    while(1)
    {
        read_command();
        if(op_cnt)
        {
            if(command_exit()) break;
            execute_command();
        }
    }
    
    sqrl_destroy(sqrl);
    if(fScript) fclose(fScript);
    return 0;
}

void read_command()
{
    size_t len = 0;
    op_cnt = 0;
    char *str = 0;
    memset(oprs, 0, sizeof(oprs));
    fputs("sqrl>", stdout);
    str = fgets(command_buf, kCommandBufSize, fin);
    if(fScript && !str)
    {
        // done reading script, return to interactive mode
        fclose(fScript);
        fScript = 0;
        fin = stdin;
    }
    else
    {
        if(fScript)
        {
            fprintf(stdout, "%s\n", command_buf);
        }
        len = strnlen(command_buf, kCommandBufSize);
        if(iscntrl(command_buf[len-1]))
        {
            command_buf[len-1] = '\0'; // remove trailing control character
        }
        char *cptr = strtok(command_buf, " ");
        while(cptr && op_cnt < kMaxOprs)
        {
            oprs[op_cnt++] = cptr;
            cptr = strtok(NULL, " ");
        }
    }
}

int command_exit()
{
    return strncmp(oprs[0], "exit", 4) == 0 ? 1 : 0;
}

void help();
int identity_create();
int identity_save();
int identity_load();
int server_query();
int server_create();
int run_script();

void execute_command()
{
    char *op = oprs[0];
    if(strcasecmp(op, "help") == 0)
    {
        help();
    }
    else if(strcasecmp(op, "create") == 0)
    {
        identity_create();
    }
    else if(strcasecmp(op, "save") == 0)
    {
        identity_save();
    }
    else if(strcasecmp(op, "load") == 0)
    {
        identity_load();
    }
    else if(strcasecmp(op, "query") == 0)
    {
        server_query();
    }
    else if(strcasecmp(op, "assoc") == 0)
    {
        server_create();
    }
    else
    {
        fprintf(stdout, "%s\n", op);
    }
}

void help()
{
    fprintf(stdout, "Usage:\nexit\nload\nsave\ncreate\nquery\nassoc\n");
}

int identity_create()
{
    if(sqrl_identity_create(sqrl))
    {
        fprintf(stdout, "Failed to create Identity\n");
    }
    else
    {
        fprintf(stdout, "Identity Created\n");
    }
    return 0;
}

int identity_save()
{
    if(op_cnt < 2)
    {
        fprintf(stdout, "Missing file path to load idenity\n");
        return 1;
    }
    char *op = oprs[1];
    FILE *stm = fopen(op, "w");
    if(stm)
    {
        if(sqrl_identity_save(sqrl, stm))
        {
            fprintf(stdout, "Failed to save identity\n");
        }
        else
        {
            fprintf(stdout, "Identity saved\n");
        }
        fclose(stm);
        
        return 0;
    }
    return 1;
}

int identity_load()
{
    const char *pswd;
    pswd = 0;
    if(op_cnt < 2)
    {
        fprintf(stdout, "Usage: load <path> [password]\n");
        return 1;
    }
    if(op_cnt > 2)
    {
        pswd = oprs[2];
    }
    FILE *stm = fopen(oprs[1], "r");
    if(stm)
    {
        if(sqrl_identity_load(sqrl, stm, pswd))
        {
            fprintf(stdout, "Failed to load identity\n");
        }
        else
        {
            fprintf(stdout, "Identity loaded\n");
        }
        fclose(stm);
        
        return 0;
    }
    return 1;
}

int server_query()
{
    if(op_cnt < 2)
    {
        fprintf(stdout, "Usage: query url [pswd]\n");
        return 1;
    }
    //sqrl_server_query(sqrl, oprs[1], oprs[2]);
    return 0;
}

int server_create()
{
    if(op_cnt < 2)
    {
        fprintf(stdout, "Usage: create url [pswd]\n");
        return 1;
    }
    sqrl_server_associate(sqrl, oprs[1], oprs[2]);
    return 0;
}

int run_script()
{
    
    return 0;
}

int parse_args(int argc, char *argv[])
{
    if(argc < 2) return 0;
    
    if(strcasecmp(argv[1], "script") == 0 && argc > 2)
    {
        fScript = fopen(argv[2], "r");
        if(fScript)
        {
            fin = fScript;
            fprintf(stdout, "Running %s\n", argv[2]);
        }
        else
        {
            fprintf(stdout, "Error loading %s\n", argv[2]);
        }
    }
    
    return 0;
}

