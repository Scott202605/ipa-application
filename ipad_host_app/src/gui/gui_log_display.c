#include "gui_log_display.h"
#include <time.h>

GtkWidget* gui_log_display_create(void) {
    GtkWidget *text_view = gtk_text_view_new();
    
    // 设置为只读
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text_view), FALSE);
    
    // 设置等宽字体
    PangoFontDescription *font_desc = 
        pango_font_description_from_string("Monospace 10");
    gtk_widget_override_font(text_view, font_desc);
    pango_font_description_free(font_desc);
    
    // 设置为左对齐
    GtkTextTag *tag = gtk_text_buffer_create_tag(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view)),
        "left_aligned", "justify", GTK_JUSTIFY_LEFT, NULL);
    
    return text_view;
}

void gui_log_display_clear(GtkTextView *text_view) {
    if (!text_view) return;
    
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(text_view);
    gtk_text_buffer_set_text(buffer, "", -1);
}

void gui_log_display_add_entry(GtkTextView *text_view,
                               const char *level,
                               const char *message,
                               const char *color) {
    if (!text_view || !message) return;
    
    // 获取当前时间
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buffer[32];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // 构建日志文本
    char *log_text = g_strdup_printf("[%s] %s\n", time_buffer, message);
    
    // 获取 buffer
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(text_view);
    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(buffer, &end_iter);
    
    // 插入文本（如果指定颜色，使用标记）
    if (color) {
        char *markup = g_strdup_printf("<span foreground='%s'>%s</span>", 
                                       color, log_text);
        gtk_text_buffer_insert_markup(buffer, &end_iter, markup, -1);
        g_free(markup);
    } else {
        gtk_text_buffer_insert(buffer, &end_iter, log_text, -1);
    }
    
    g_free(log_text);
    
    // 自动滚动到底部
    GtkTextMark *mark = gtk_text_buffer_get_insert(buffer);
    gtk_text_view_scroll_to_mark(text_view, mark, 0.0, TRUE, 0.0, 0.0);
}
