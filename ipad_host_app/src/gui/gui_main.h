#ifndef GUI_MAIN_H
#define GUI_MAIN_H

#include <gtk/gtk.h>
#include "ipad_app_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// 主窗口结构
typedef struct {
    GtkWidget *window;              // 主窗口
    GtkWidget *device_status_label; // 设备状态标签
    GtkWidget *euicc_status_label;  // eUICC 状态标签
    
    // API 选择树
    GtkWidget *api_tree_view;
    GtkListStore *api_tree_store;
    
    // 参数输入区
    GtkWidget *param_container;
    GtkWidget *param_input_frame;
    GtkGrid *param_grid;
    
    // 日志显示
    GtkWidget *log_text_view;
    GtkTextBuffer *log_buffer;
    
    // 当前选中的 API
    const api_descriptor_t *current_api;
    
    // 模拟响应模式
    GtkWidget *mock_response_check;
    GtkWidget *mock_error_code_entry;
    bool mock_mode_enabled;
    
    // 日志文件
    FILE *log_file;
} main_window_t;

/**
 * @brief 创建并初始化主窗口
 * @return 主窗口结构指针
 */
main_window_t* gui_main_create_window(void);

/**
 * @brief 运行主窗口事件循环
 * @param window 主窗口指针
 */
void gui_main_run(main_window_t *window);

/**
 * @brief 销毁主窗口
 * @param window 主窗口指针
 */
void gui_main_destroy(main_window_t *window);

/**
 * @brief 更新设备连接状态
 * @param window 主窗口指针
 * @param connected 是否已连接
 */
void gui_main_update_device_status(main_window_t *window, bool connected);

/**
 * @brief 更新 eUICC 状态
 * @param window 主窗口指针
 * @param status eUICC 状态字符串
 */
void gui_main_update_euicc_status(main_window_t *window, const char *status);

/**
 * @brief 添加日志条目
 * @param window 主窗口指针
 * @param level 日志级别 ("INFO", "ERROR", "DEBUG" 等)
 * @param format 格式化字符串
 * @param ... 可变参数
 */
void gui_main_add_log(main_window_t *window, const char *level, 
                     const char *format, ...);

/**
 * @brief 设置当前 API 并刷新参数输入面板
 * @param window 主窗口指针
 * @param api API 描述符，类别节点传 NULL
 */
void gui_main_set_current_api(main_window_t *window, const api_descriptor_t *api);

#ifdef __cplusplus
}
#endif

#endif // GUI_MAIN_H
