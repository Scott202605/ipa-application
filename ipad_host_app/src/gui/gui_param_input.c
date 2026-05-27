#include "gui_param_input.h"
#include "app_api_definitions.h"
#include <string.h>

// 动态创建的输入控件容器
typedef struct {
    GtkWidget *container;
    GList *widget_list;  // 存储所有创建的子部件
} param_input_widgets_t;

static param_input_widgets_t *g_input_widgets = NULL;

static GtkWidget* create_string_input(const char *param_name, const char *default_value);
static GtkWidget* create_int_input(const char *param_name, int default_value);
static GtkWidget* create_bool_input(const char *param_name, bool default_value);
static GtkWidget* create_enum_input(const char *param_name, const char **enum_values);

GtkWidget* gui_param_input_create(main_window_t *window, 
                                  const api_descriptor_t *api) {
    if (g_input_widgets && g_input_widgets->container) {
        gui_param_input_destroy(window);
    }
    
    g_input_widgets = g_new0(param_input_widgets_t, 1);
    g_input_widgets->widget_list = NULL;
    
    // 创建容器
    GtkWidget *container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(container), 10);
    g_input_widgets->container = container;
    
    if (!api) {
        // 没有选中 API，显示提示
        GtkWidget *label = gtk_label_new("请从左侧选择要调用的 API");
        gtk_box_pack_start(GTK_BOX(container), label, FALSE, FALSE, 5);
        gtk_widget_set_valign(label, GTK_ALIGN_START);
        return container;
    }
    
    // API 名称标签
    GtkWidget *title = gtk_label_new(NULL);
    char *title_text = g_strdup_printf("<b>%s</b>\n%s", 
                                       api->display_name, api->description);
    gtk_label_set_markup(GTK_LABEL(title), title_text);
    g_free(title_text);
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_box_pack_start(GTK_BOX(container), title, FALSE, FALSE, 5);
    
    GtkWidget *separator = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(container), separator, FALSE, FALSE, 5);
    
    // 创建参数输入框（根据 API 类型动态创建）
    // 示例：手动创建一些参数输入
    GtkWidget *params_label = gtk_label_new("<b>参数输入:</b>");
    gtk_label_set_use_markup(GTK_LABEL(params_label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(params_label), 0.0);
    gtk_box_pack_start(GTK_BOX(container), params_label, FALSE, FALSE, 5);
    
    // 示例参数输入（实际应该根据 API 定义自动生成）
    // 这里以几个常见参数为例展示实现
    GtkWidget *param_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(param_grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(param_grid), 10);
    gtk_box_pack_start(GTK_BOX(container), param_grid, FALSE, FALSE, 0);
    
    // ICCID 输入（字符串类型示例）
    GtkWidget *iccid_label = gtk_label_new("ICCID:");
    gtk_label_set_xalign(GTK_LABEL(iccid_label), 0.0);
    GtkWidget *iccid_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(iccid_entry), 
                                   "89 位数字，如：89860123456789012345");
    gtk_widget_set_size_request(iccid_entry, 300, -1);
    g_input_widgets->widget_list = g_list_append(g_input_widgets->widget_list, 
                                                  iccid_entry);
    gtk_grid_attach(GTK_GRID(param_grid), iccid_label, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(param_grid), iccid_entry, 1, 0, 1, 1);
    
    // SM-DP+ 地址输入（字符串类型示例）
    GtkWidget *smdp_label = gtk_label_new("SM-DP+ 地址:");
    gtk_label_set_xalign(GTK_LABEL(smdp_label), 0.0);
    GtkWidget *smdp_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(smdp_entry), 
                                   "smdp.example.com");
    gtk_widget_set_size_request(smdp_entry, 300, -1);
    g_input_widgets->widget_list = g_list_append(g_input_widgets->widget_list, 
                                                  smdp_entry);
    gtk_grid_attach(GTK_GRID(param_grid), smdp_label, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(param_grid), smdp_entry, 1, 1, 1, 1);
    
    // 确认码输入（可选参数示例）
    GtkWidget *confirm_label = gtk_label_new("确认码:");
    gtk_label_set_xalign(GTK_LABEL(confirm_label), 0.0);
    GtkWidget *confirm_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(confirm_entry), "4-8 位字母数字，可选");
    gtk_widget_set_size_request(confirm_entry, 300, -1);
    g_input_widgets->widget_list = g_list_append(g_input_widgets->widget_list, 
                                                  confirm_entry);
    gtk_grid_attach(GTK_GRID(param_grid), confirm_label, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(param_grid), confirm_entry, 1, 2, 1, 1);
    
    // 激活策略选择（枚举类型示例）
    GtkWidget *policy_label = gtk_label_new("激活策略:");
    gtk_label_set_xalign(GTK_LABEL(policy_label), 0.0);
    GtkWidget *policy_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(policy_combo), 
                                   "PROFILE_CLASS_TEST");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(policy_combo), 
                                   "PROFILE_CLASS_PROVISIONING");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(policy_combo), 
                                   "PROFILE_CLASS_OPERATIONAL");
    gtk_combo_box_set_active(GTK_COMBO_BOX(policy_combo), 2);
    g_input_widgets->widget_list = g_list_append(g_input_widgets->widget_list, 
                                                  policy_combo);
    gtk_grid_attach(GTK_GRID(param_grid), policy_label, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(param_grid), policy_combo, 1, 3, 1, 1);
    
    // 返回错误码设置（手动响应注入用）
    GtkWidget *error_label = gtk_label_new("返回错误码:");
    gtk_label_set_xalign(GTK_LABEL(error_label), 0.0);
    GtkWidget *error_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(error_combo), "eOk (0)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(error_combo), "eFatal (1)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(error_combo), "eNotSupported (2)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(error_combo), "eBadArg (4)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(error_combo), "eNoMem (9)");
    gtk_combo_box_set_active(GTK_COMBO_BOX(error_combo), 0);
    g_input_widgets->widget_list = g_list_append(g_input_widgets->widget_list, 
                                                  error_combo);
    gtk_grid_attach(GTK_GRID(param_grid), error_label, 0, 4, 1, 1);
    gtk_grid_attach(GTK_GRID(param_grid), error_combo, 1, 4, 1, 1);
    
    return container;
}

void gui_param_input_destroy(main_window_t *window) {
    (void)window;
    
    if (g_input_widgets) {
        if (g_input_widgets->widget_list) {
            g_list_free(g_input_widgets->widget_list);
        }
        if (g_input_widgets->container) {
            gtk_widget_destroy(g_input_widgets->container);
        }
        g_free(g_input_widgets);
        g_input_widgets = NULL;
    }
}

int gui_param_input_get_value(main_window_t *window,
                              const char *param_name,
                              char *buffer,
                              size_t buffer_size) {
    (void)window;
    (void)param_name;
    (void)buffer;
    (void)buffer_size;
    
    // TODO: 实现参数值获取
    // 需要根据 param_name 找到对应的输入控件并读取值
    return -1;
}

bool gui_param_input_get_bool(main_window_t *window, const char *param_name) {
    // TODO: 实现
    (void)window;
    (void)param_name;
    return false;
}

int gui_param_input_get_int(main_window_t *window, const char *param_name) {
    // TODO: 实现
    (void)window;
    (void)param_name;
    return 0;
}

static GtkWidget* create_string_input(const char *param_name, const char *default_value) {
    (void)param_name;
    GtkWidget *entry = gtk_entry_new();
    if (default_value) {
        gtk_entry_set_text(GTK_ENTRY(entry), default_value);
    }
    return entry;
}

static GtkWidget* create_int_input(const char *param_name, int default_value) {
    (void)param_name;
    GtkWidget *spin = gtk_spin_button_new_with_range(-1000000, 1000000, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(spin), default_value);
    return spin;
}

static GtkWidget* create_bool_input(const char *param_name, bool default_value) {
    (void)param_name;
    GtkWidget *check = gtk_check_button_new();
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), default_value);
    return check;
}

static GtkWidget* create_enum_input(const char *param_name, const char **enum_values) {
    (void)param_name;
    GtkWidget *combo = gtk_combo_box_text_new();
    
    if (enum_values) {
        for (int i = 0; enum_values[i] != NULL; i++) {
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), enum_values[i]);
        }
        gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
    }
    
    return combo;
}
