#ifndef GUI_API_TREE_H
#define GUI_API_TREE_H

#include <gtk/gtk.h>
#include "ipad_app_types.h"
#include "gui/gui_main.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 创建 API 树形视图
 * @param window 主窗口指针
 * @return 树形视图部件
 */
GtkWidget* gui_api_tree_create(main_window_t *window);

/**
 * @brief 填充 API 树数据
 * @param tree_store 树存储对象
 */
void gui_api_tree_populate(GtkTreeStore *tree_store);

/**
 * @brief 获取当前选中的 API 描述符
 * @param tree_view 树视图
 * @return API 描述符指针，未选中则返回 NULL
 */
const api_descriptor_t* gui_api_tree_get_selected_api(GtkTreeView *tree_view);

#ifdef __cplusplus
}
#endif

#endif // GUI_API_TREE_H
