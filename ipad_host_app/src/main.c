#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include "gui/gui_main.h"
#include "ipad_wrapper.h"

static main_window_t *g_main_window = NULL;

// 事件回调函数
static void on_event_callback(ipa_event_type_t event_type, void *event_data) {
    if (!g_main_window) return;
    
    switch (event_type) {
        case IPA_EVENT_INITIALIZATION_SUCCESS:
            gui_main_add_log(g_main_window, "INFO", "IPA 初始化成功");
            gui_main_update_device_status(g_main_window, true);
            gui_main_update_euicc_status(g_main_window, "正常");
            break;
            
        case IPA_EVENT_INITIALIZATION_FAILED:
            gui_main_add_log(g_main_window, "ERROR", "IPA 初始化失败");
            gui_main_update_device_status(g_main_window, false);
            gui_main_update_euicc_status(g_main_window, "未知");
            break;
            
        case IPA_EVENT_PROVISIONING_NEEDED:
            gui_main_add_log(g_main_window, "INFO", "需要配置");
            break;
            
        case IPA_EVENT_SERVICE_CONNECT_SUCCESS:
            gui_main_add_log(g_main_window, "INFO", "服务连接成功");
            break;
            
        default:
            gui_main_add_log(g_main_window, "DEBUG", "未知事件类型：%d", event_type);
            break;
    }
}

int main(int argc, char *argv[]) {
    // 初始化 GTK
    gtk_init(&argc, &argv);
    
    // 初始化日志
    printf("IPA 上位机程序启动...\n");
    
    // 创建主窗口
    g_main_window = gui_main_create_window();
    if (!g_main_window) {
        fprintf(stderr, "创建主窗口失败\n");
        return EXIT_FAILURE;
    }
    
    gui_main_add_log(g_main_window, "INFO", "IPA 上位机程序已启动 (版本 1.0.0)");
    gui_main_add_log(g_main_window, "INFO", "SDK 版本：%s", ipad_wrapper_get_version());
    
    // 初始化 IPAd SDK
    gui_main_add_log(g_main_window, "INFO", "正在初始化 IPAd SDK...");
    int init_result = ipad_wrapper_init(NULL);
    if (init_result != 0) {
        gui_main_add_log(g_main_window, "ERROR", "SDK 初始化失败：%d", init_result);
    } else {
        gui_main_add_log(g_main_window, "INFO", "SDK 初始化成功");
    }
    
    // 注册任务回调
    ipa_register_task_callbacks(NULL); // 暂时使用默认回调
    
    // 运行主窗口
    gui_main_run(g_main_window);
    
    // 反初始化 SDK
    gui_main_add_log(g_main_window, "INFO", "正在关闭 SDK...");
    ipad_wrapper_deinit();
    
    // 销毁窗口
    gui_main_destroy(g_main_window);
    
    return EXIT_SUCCESS;
}
