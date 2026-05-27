#ifndef GUI_PARAM_INPUT_H
#define GUI_PARAM_INPUT_H

#include <gtk/gtk.h>
#include "ipad_app_types.h"
#include "gui/gui_main.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 创建参数输入面板
 * @param window 主窗口指针
 * @param api API 描述符
 * @return 参数输入框架部件
 */
GtkWidget* gui_param_input_create(main_window_t *window, 
                                  const api_descriptor_t *api);

/**
 * @brief 销毁参数输入面板
 * @param window 主窗口指针
 */
void gui_param_input_destroy(main_window_t *window);

/**
 * @brief 获取参数输入值
 * @param window 主窗口指针
 * @param param_name 参数名
 * @param buffer 输出缓冲区
 * @param buffer_size 缓冲区大小
 * @return 0 成功，-1 失败
 */
int gui_param_input_get_value(main_window_t *window, 
                              const char *param_name,
                              char *buffer, 
                              size_t buffer_size);

/**
 * @brief 获取布尔参数值
 * @param window 主窗口指针
 * @param param_name 参数名
 * @return true 或 false
 */
bool gui_param_input_get_bool(main_window_t *window, const char *param_name);

/**
 * @brief 获取整数参数值
 * @param window 主窗口指针
 * @param param_name 参数名
 * @return 整数值
 */
int gui_param_input_get_int(main_window_t *window, const char *param_name);

#ifdef __cplusplus
}
#endif

#endif // GUI_PARAM_INPUT_H
