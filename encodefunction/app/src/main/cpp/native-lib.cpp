#include <jni.h>
#include <string>
#include <elf.h>
#include <unistd.h>
#include <android/log.h>
#include <sys/mman.h>

unsigned long getLibAddr(){
    unsigned long ret=0;
    char name[]="libnative-lib.so";
    char buf[4096],*temp;
    int pid=getpid();
    FILE *fp;
    sprintf(buf,"/proc/%d/maps",pid);
    fp=fopen(buf,"r");
    if (fp!=NULL){
        while (fgets(buf,sizeof(buf),fp)){
            if (strstr(buf,name)){
                temp=strtok(buf,"-");
                ret=strtoul(temp,NULL,16);
                break;
            }
        }
        fclose(fp);
    }
    return ret;
}

void init_getString() __attribute__((constructor));

static void print_debug(const char *msg){
    __android_log_print(ANDROID_LOG_INFO,"JNITag","%s",msg);
}

void init_getString(){
    unsigned int nblock;
    unsigned int nsize;
    unsigned long base;
    unsigned long text_addr;
    Elf32_Ehdr *ehdr;

    base=getLibAddr();
    ehdr= (Elf32_Ehdr *)base;
    text_addr=ehdr->e_flags+base;
    nblock=ehdr->e_entry;
    nsize=nblock/4096+(nblock%4096==0?0:1);

    if (mprotect((void *)(text_addr/PAGE_SIZE*PAGE_SIZE),4096*nsize,
            PROT_READ|PROT_EXEC|PROT_WRITE)!=0){
        print_debug("修改内存权限失败");
    }
    for (int i = 0; i < nblock; ++i) {
        char *addr=(char *)(text_addr+i);
        *addr=~(*addr);
    }
    if (mprotect((void *)(text_addr/PAGE_SIZE*PAGE_SIZE),4096*nsize,
            PROT_READ|PROT_EXEC)!=0){
        print_debug("修改内存权限失败");
    }
    print_debug("解密完成");
}

static unsigned elfhash(const char *_name){
    const unsigned char *name= reinterpret_cast<const unsigned char *>(_name);
    unsigned h=0,g;
    while (*name){
        h=(h<<4)+*name++;
        g=h&0xf0000000;
        h^=g;
        h^=g>>24;
    }
    return h;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_encodefunction_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Native method return!";
    return env->NewStringUTF(hello.c_str());
}