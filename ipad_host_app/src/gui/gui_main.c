#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <gtk/gtk.h>

#include "gui/gui_main.h"
#include "gui/gui_api_tree.h"
#include "gui/gui_param_input.h"
#include "gui/gui_log_display.h"
#include "ipad_wrapper.h"

// API 列表定义
#include "app_api_definitions.h"

// 窗口默认大小
#define WINDOW_WIDTH 1200
#define WINDOW_HEIGHT 800

static void on_api_selected(GtkTreeSelection *selection, gpointer user_data);
static void on_call_api_clicked(GtkWidget *button, gpointer user_data);
static void on_clear_params_clicked(GtkWidget *button, gpointer user_data);
static void on_export_log_clicked(GtkWidget *button, gpointer user_data);
static void on_window_destroy(GtkWidget *window, gpointer user_data);

main_window_t* gui_main_create_window(void) {
    main_window_t *window = g_new0(main_window_t, 1);
    if (!window) return NULL;
    
    // 创建主窗口
    window->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window->window), "IPA 上位机程序 - IPAd SDK Controller");
    gtk_window_set_default_size(GTK_WINDOW(window->window), WINDOW_WIDTH, WINDOW_HEIGHT);
    gtk_container_set_border_width(GTK_CONTAINER(window->window), 5);
    
    g_signal_connect(window->window, "destroy", G_CALLBACK(on_window_destroy), window);
    
    // 创建主布局容器
    GtkWidget *main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window->window), main_vbox);
    
    // 顶部状态栏
    GtkWidget *status_frame = gtk_frame_new("设备状态");
    gtk_box_pack_start(GTK_BOX(main_vbox), status_frame, FALSE, FALSE, 0);
    
    GtkWidget *status_grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(status_frame), status_grid);
    gtk_grid_set_column_spacing(GTK_GRID(status_grid), 20);
    gtk_container_set_border_width(GTK_CONTAINER(status_grid), 10);
    
    // 设备连接状态
    GtkWidget *conn_label = gtk_label_new("连接状态:");
    gtk_grid_attach(GTK_GRID(status_grid), conn_label, 0, 0, 1, 1);
    window->device_status_label = gtk_label_new("未连接");
    gtk_label_set_xalign(GTK_LABEL(window->device_status_label), 0.0);
    gtk_grid_attach(GTK_GRID(status_grid), window->device_status_label, 1, 0, 1, 1);
    
    // eUICC 状态
    GtkWidget *euicc_label = gtk_label_new("eUICC 状态:");
    gtk_grid_attach(GTK_GRID(status_grid), euicc_label, 2, 0, 1, 1);
    window->euicc_status_label = gtk_label_new("未知");
    gtk_label_set_xalign(GTK_LABEL(window->euicc_status_label), 0.0);
    gtk_grid_attach(GTK_GRID(status_grid), window->euicc_status_label, 3, 0, 1, 1);
    
    // 中间区域（左侧 API 树，右侧参数输入）
    GtkWidget *center_hbox = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(main_vbox), center_hbox, TRUE, TRUE, 0);
    gtk_paned_set_position(GTK_PANED(center_hbox), 400);
    
    // 左侧 API 树
    GtkWidget *api_frame = gtk_frame_new("可用 API");
    gtk_paned_add1(GTK_PANED(center_hbox), api_frame);
    
    GtkWidget *api_scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(api_scrolled),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(api_frame), api_scrolled);
    
    window->api_tree_view = gui_api_tree_create(window);
    gtk_container_add(GTK_CONTAINER(api_scrolled), window->api_tree_view);
    
    // 右侧参数输入区
    GtkWidget *param_frame = gtk_frame_new("参数设置");
    gtk_paned_add2(GTK_PANED(center_hbox), param_frame);
    
    window->param_input_frame = gui_param_input_create(window, NULL);
    gtk_container_add(GTK_CONTAINER(param_frame), window->param_input_frame);
    
    // 操作按钮区域
    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(main_vbox), button_box, FALSE, FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(button_box), 5);
    
    GtkWidget *call_button = gtk_button_new_with_label("调用 API");
    gtk_box_pack_start(GTK_BOX(button_box), call_button, FALSE, FALSE, 0);
    g_signal_connect(call_button, "clicked", G_CALLBACK(on_call_api_clicked), window);
    
    GtkWidget *clear_button = gtk_button_new_with_label("清除参数");
    gtk_box_pack_start(GTK_BOX(button_box), clear_button, FALSE, FALSE, 0);
    g_signal_connect(clear_button, "clicked", G_CALLBACK(on_clear_params_clicked), window);
    
    window->mock_response_check = gtk_check_button_new_with_label("启用手动响应参数注入");
    gtk_box_pack_start(GTK_BOX(button_box), window->mock_response_check, FALSE, FALSE, 0);
    g_signal_connect(window->mock_response_check, "toggled", 
                     G_CALLBACK((void(*)(void))gtk_widget_set_sensitive), 
                     gtk_check_button_get_active(GTK_CHECK_BUTTON(window->mock_response_check)) ? 
                     gtk_button_new_with_label("设置") : NULL);
    
    GtkWidget *export_button = gtk_button_new_with_label("导出日志");
    gtk_box_pack_end(GTK_BOX(button_box), export_button, FALSE, FALSE, 0);
    g_signal_connect(export_button, "clicked", G_CALLBACK(on_export_log_clicked), window);
    
    // 底部日志显示区
    GtkWidget *log_frame = gtk_frame_new("日志/响应");
    gtk_box_pack_start(GTK_BOX(main_vbox), log_frame, FALSE, TRUE, 0);
    
    GtkWidget *log_scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(log_scrolled),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(log_scrolled, -1, 200);
    gtk_container_add(GTK_CONTAINER(log_frame), log_scrolled);
    
    window->log_text_view = gui_log_display_create();
    window->log_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(window->log_text_view));
    gtk_container_add(GTK_CONTAINER(log_scrolled), window->log_text_view);
    
    // 初始化状态
    window->current_api = NULL;
    window->mock_mode_enabled = false;
    window->log_file = NULL;
    
    return window;
}

void gui_main_run(main_window_t *window) {
    if (window && window->window) {
        gtk_widget_show_all(window->window);
        gtk_main();
    }
}

void gui_main_destroy(main_window_t *window) {
    if (!window) return;
    
    if (window->log_file) {
        fclose(window->log_file);
    }
    
    if (window->window) {
        gtk_widget_destroy(window->window);
    }
    
    g_free(window);
}

void gui_main_update_device_status(main_window_t *window, bool connected) {
    if (!window || !window->device_status_label) return;
    
    const char *status_text = connected ? "已连接" : "未连接";
    gtk_label_set_text(GTK_LABEL(window->device_status_label), status_text);
    
    // 设置颜色
    const char *color = connected ? "#00AA00" : "#AA0000";
    char *markup = g_strdup_printf("<span foreground='%s' weight='bold'>%s</span>", 
                                   color, status_text);
    gtk_label_set_markup(GTK_LABEL(window->device_status_label), markup);
    g_free(markup);
}

void gui_main_update_euicc_status(main_window_t *window, const char *status) {
    if (!window || !window->euicc_status_label) return;
    
    gtk_label_set_text(GTK_LABEL(window->euicc_status_label), status);
}

void gui_main_add_log(main_window_t *window, const char *level, 
                     const char *format, ...) {
    if (!window || !window->log_buffer) return;
    
    // 获取当前时间
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buffer[32];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // 格式化日志内容
    va_list args;
    va_start(args, format);
    char message[1024];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // 设置颜色
    const char *color;
    if (strcmp(level, "ERROR") == 0) color = "#FF0000";
    else if (strcmp(level, "WARN") == 0) color = "#FF8800";
    else if (strcmp(level, "INFO") == 0) color = "#008800";
    else color = "#000000";
    
    // 构建带格式的日志文本
    char *log_text = g_strdup_printf("[%s] <b>%s</b> %s\n", time_buffer, level, message);
    
    // 获取 buffer 末尾的 iter
    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(window->log_buffer, &end_iter);
    
    // 插入带格式的文本（简单标记）
    gtk_text_buffer_insert_markup(window->log_buffer, &end_iter, log_text, -1);
    
    // 自动滚动到底部
    GtkWidget *log_view = window->log_text_view;
    GtkTextMark *mark = gtk_text_buffer_get_insert(window->log_buffer);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(log_view), mark, 0.0, TRUE, 0.0, 0.0);
    
    g_free(log_text);
    
    // 同时写入 log 文件
    if (window->log_file) {
        fprintf(window->log_file, "[%s] %s %s\n", time_buffer, level, message);
        fflush(window->log_file);
    }
}

// 回调函数实现
static void on_api_selected(GtkTreeSelection *selection, gpointer user_data) {
    main_window_t *window = (main_window_t*)user_data;
    
    if (!window) return;
    
    GtkTreeIter iter;
    GtkTreeModel *model;
    
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        // 获取 API 描述符
        const api_descriptor_t *api;
        gtk_tree_model_get(model, &iter, 1, &api, -1);
        
        if (api && api->category != API_CATEGORY_INIT) { // INIT 分类是根节点
            // 清除旧的参数输入框
            gui_param_input_destroy(window);
            
            // 创建新的参数输入框
            window->param_input_frame = gui_param_input_create(window, api);
            GtkWidget *parent = gtk_widget_get_parent(window->param_input_frame);
            if (parent && GTK_IS_BIN(parent)) {
                gtk_container_add(GTK_CONTAINER(parent), window->param_input_frame);
                gtk_widget_show_all(window->param_input_frame);
            }
            
            gui_main_add_log(window, "INFO", "选中 API: %s", api->display_name);
        }
    }
}

static void on_call_api_clicked(GtkWidget *button, gpointer user_data) {
    main_window_t *window = (main_window_t*)user_data;
    if (!window || !window->current_api) return;
    
    gui_main_add_log(window, "INFO", "调用 API: %s", window->current_api->display_name);
    
    // TODO: 实现 API 调用逻辑
    gui_main_add_log(window, "INFO", "API 调用成功（未实现）");
}

static void on_clear_params_clicked(GtkWidget *button, gpointer user_data) {
    main_window_t *window = (main_window_t*)user_data;
    if (!window) return;
    
    gui_main_add_log(window, "INFO", "清除参数");
    
    // TODO: 清除参数输入框
}

static void on_export_log_clicked(GtkWidget *button, gpointer user_data) {
    main_window_t *window = (main_window_t*)user_data;
    if (!window) return;
    
    // TODO: 导出日志到文件
    gui_main_add_log(window, "INFO", "导出日志功能待实现");
}

static void on_window_destroy(GtkWidget *window, gpointer user_data) {
    (void)window;
    main_window_t *win = (main_window_t*)user_data;
    
    if (win->log_file) {
        fclose(win->log_file);
        win->log_file = NULL;
    }
    
    gtk_main_quit();
}
