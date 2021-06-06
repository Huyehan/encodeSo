#include <jni.h>
#include <string>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <android/log.h>

//jstring getString(JNIEnv* env) __attribute__((section (".mytext")));
//jstring getString(JNIEnv* env){
//    return env->NewStringUTF("Native method return!");
//}
extern "C" jstring Java_com_example_encodesection_MainActivity_stringFromJNI(JNIEnv* env,jobject /* this */) __attribute__((section(".mytext")));
void init_getString() __attribute__((constructor));
unsigned long getLibAddr();

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_encodesection_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    return env->NewStringUTF("Native method return!");;
}

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

void init_getString(){
    char name[15];
    unsigned int nblock;
    unsigned int nsize;
    unsigned long base;
    unsigned long text_addr;
    unsigned int i;
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr;

    // 获取so的起始位置
    base=getLibAddr();

    // 获取指定section的偏移值和大小
    ehdr= (Elf32_Ehdr *)base;
    text_addr=ehdr->e_flags+base;
    nblock=ehdr->e_entry;
    nsize=nblock/4096+(nblock%4096==0?0:1);

    // 修改内存操作权限
    if (mprotect((void *) (text_addr/PAGE_SIZE*PAGE_SIZE),4096*nsize,
            PROT_READ|PROT_EXEC|PROT_WRITE)!=0){
        __android_log_print(ANDROID_LOG_INFO,"TAG","修改内存权限失败");
    }
    // 解密
    for (int i=0;i<nblock;i++){
        char *addr= (char *)(text_addr + i);
        *addr=~(*addr);
    }
    if (mprotect((void *) (text_addr/PAGE_SIZE*PAGE_SIZE),4096*nsize,
                 PROT_READ|PROT_EXEC)!=0){
        __android_log_print(ANDROID_LOG_INFO,"TAG","修改内存权限失败");
    }
    __android_log_print(ANDROID_LOG_INFO,"TAG","解密完成");
}