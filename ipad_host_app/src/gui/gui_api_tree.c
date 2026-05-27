#include "gui_api_tree.h"

static void on_api_tree_selection_changed(GtkTreeSelection *selection, gpointer user_data);

GtkWidget* gui_api_tree_create(main_window_t *window) {
    GtkWidget *tree_view = gtk_tree_view_new();
    
    // 创建树存储（列：类别名称，API 指针）
    GtkTreeStore *tree_store = gtk_tree_store_new(2, G_TYPE_STRING, G_TYPE_POINTER);
    gtk_tree_view_set_model(GTK_TREE_VIEW(tree_view), GTK_TREE_MODEL(tree_store));
    g_object_unref(tree_store);
    
    // 渲染器
    GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *column = gtk_tree_view_column_new_with_attributes(
        "API 名称", renderer, "text", 0, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree_view), column);
    
    // 展开所有节点
    gtk_tree_view_expand_all(GTK_TREE_VIEW(tree_view));
    
    // 填充数据
    gui_api_tree_populate(tree_store);
    
    // 连接选择信号
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
    gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);
    g_signal_connect(selection, "changed", 
                     G_CALLBACK(on_api_tree_selection_changed), window);
    
    return tree_view;
}

void gui_api_tree_populate(GtkTreeStore *tree_store) {
    const api_category_entry_t *cat_entry = ALL_API_CATEGORIES;
    
    while (cat_entry->category_name != NULL) {
        // 创建类别节点
        GtkTreeIter parent_iter;
        gtk_tree_store_append(tree_store, &parent_iter, NULL);
        gtk_tree_store_set(tree_store, &parent_iter,
                          0, cat_entry->category_name,
                          1, NULL,  // API 指针为 NULL，表示是类别节点
                          -1);
        
        // 添加该类别下的 API
        if (cat_entry->api_list) {
            const api_descriptor_t *api = cat_entry->api_list;
            while (api->name != NULL) {
                GtkTreeIter child_iter;
                gtk_tree_store_append(tree_store, &child_iter, &parent_iter);
                gtk_tree_store_set(tree_store, &child_iter,
                                  0, api->display_name,
                                  1, &api,  // 存储 API 描述符指针
                                  -1);
                api++;
            }
        }
        
        cat_entry++;
    }
}

const api_descriptor_t* gui_api_tree_get_selected_api(GtkTreeView *tree_view) {
    GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
    GtkTreeIter iter;
    GtkTreeModel *model;
    
    if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
        return NULL;
    }
    
    const api_descriptor_t *api;
    gtk_tree_model_get(model, &iter, 1, &api, -1);
    
    return api;
}

static void on_api_tree_selection_changed(GtkTreeSelection *selection, gpointer user_data) {
    main_window_t *window = (main_window_t*)user_data;
    if (!window) return;
    
    GtkTreeIter iter;
    GtkTreeModel *model;
    
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        const api_descriptor_t *api;
        gtk_tree_model_get(model, &iter, 1, &api, -1);
        
        window->current_api = api;
        
        // 如果选中的是 API（不是类别），触发参数输入更新
        if (api && api->category != API_CATEGORY_INIT) {
            // 在 gui_main.c 中处理
        }
    }
}
