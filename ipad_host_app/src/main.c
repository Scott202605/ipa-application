#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include "gui/gui_main.h"
#include "ipad_wrapper.h"
#include "config_manager.h"

static main_window_t *g_main_window = NULL;

static void print_usage(const char *program_name) {
    printf("Usage: %s [--config <path>] [--help]\n", program_name);
    printf("\n");
    printf("Options:\n");
    printf("  -c, --config <path>  Load JSON configuration from path\n");
    printf("  -h, --help           Show this help message\n");
}

int main(int argc, char *argv[]) {
    const char *config_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "缺少配置文件路径\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            config_path = argv[++i];
            continue;
        }

        fprintf(stderr, "未知参数: %s\n", argv[i]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // 初始化 GTK
    if (!gtk_init_check(&argc, &argv)) {
        fprintf(stderr, "GTK 初始化失败：请确认已安装 GTK3，且 DISPLAY/Wayland 会话可用。\n");
        return EXIT_FAILURE;
    }
    
    // 初始化日志
    printf("IPA 上位机程序启动...\n");

    if (config_init(config_path) != 0) {
        fprintf(stderr, "配置初始化失败，将继续使用默认配置\n");
    }
    
    // 创建主窗口
    g_main_window = gui_main_create_window();
    if (!g_main_window) {
        fprintf(stderr, "创建主窗口失败\n");
        return EXIT_FAILURE;
    }
    
    gui_main_add_log(g_main_window, "INFO", "IPA 上位机程序已启动 (版本 1.1.0)");
    if (config_path) {
        gui_main_add_log(g_main_window, "INFO", "配置文件: %s", config_path);
    } else {
        gui_main_add_log(g_main_window, "INFO", "未指定配置文件，使用默认配置");
    }
    gui_main_add_log(g_main_window, "INFO", "SDK 版本：%s", ipad_wrapper_get_version());
    
    // 初始化 IPAd SDK
    gui_main_add_log(g_main_window, "INFO", "正在初始化 IPAd SDK...");
    int init_result = ipad_wrapper_init(config_path);
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
    config_deinit();
    
    return EXIT_SUCCESS;
}
