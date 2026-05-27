#ifndef GUI_LOG_DISPLAY_H
#define GUI_LOG_DISPLAY_H

#include <gtk/gtk.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 创建日志显示文本视图
 * @return 文本视图部件
 */
GtkWidget* gui_log_display_create(void);

/**
 * @brief 清空日志
 * @param text_view 文本视图
 */
void gui_log_display_clear(GtkTextView *text_view);

/**
 * @brief 添加日志条目
 * @param text_view 文本视图
 * @param level 日志级别
 * @param message 日志消息
 * @param color 文本颜色（十六进制，如 "#FF0000"）
 */
void gui_log_display_add_entry(GtkTextView *text_view, 
                               const char *level,
                               const char *message,
                               const char *color);

#ifdef __cplusplus
}
#endif

#endif // GUI_LOG_DISPLAY_H
