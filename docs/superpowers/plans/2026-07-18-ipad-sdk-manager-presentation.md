# IPAd SDK 与 IPAd Manager 演示稿 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 基于当前仓库代码和指定 Business Review 模板，生成一份约 40–50 页、可按管理层/客户/研发受众裁剪的 IPAd SDK 与 IPAd Manager 中文技术演示稿。

**Architecture:** 使用 `@oai/artifact-tool` 导入并编辑指定 PowerPoint 模板，通过仓库事实清单驱动页面内容，按“全景—SDK—Manager—部署—状态—附录”组织。所有中间审计材料放在系统临时目录，最终生成脚本和 PPTX 分别保存在 `tools/presentation/` 与 `outputs/`，并通过模板一致性、逐页渲染、溢出和结构检查验收。

**Tech Stack:** PowerPoint/PPTX、JavaScript ES Modules、`@oai/artifact-tool`、Codex bundled presentation tools、PowerPoint template-following QA、Python 渲染与幻灯片测试脚本。

## Global Constraints

- 严格使用 `openai-templates:artifact-template-business-review` 的 `reference.pptx`，不得混用其他主题。
- 事实必须来自当前仓库代码和文档；发布说明只作为历史材料并与代码交叉核对。
- 所有能力必须标记为“已实现并接入”“底层存在但接入不完整”“占位/未验证”或“建议演进”。
- 最终演示稿采用 16:9、白/浅灰背景、钴蓝主色和黑灰辅助色。
- 每页标记推荐受众：管理、客户、研发。
- 中间 prose 文件使用 `.txt`，放在仓库外临时目录。
- 最终文件固定输出为 `outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx`。
- 不修改 SDK 和 Manager 产品源码，不覆盖用户已有未跟踪文件。

---

## File Structure

- Create: `tools/presentation/build_ipad_sdk_manager_deck.mjs` — 导入模板、创建页面、写入内容、导出 PPTX。
- Create: `tools/presentation/ipad_deck_content.mjs` — 集中保存页级标题、正文、表格、图形数据和受众标签。
- Create: `tools/presentation/ipad_deck_styles.mjs` — 模板目标映射、颜色、字体和通用布局辅助函数。
- Create: `outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx` — 最终交付文件。
- Create in temp: `template-audit.txt` — 每个模板页的版式、占位符和用途审计。
- Create in temp: `template-frame-map.json` — 内容语义到模板 frame/placeholder 的映射。
- Create in temp: `deviation-log.txt` — 模板偏差记录；理想结果为空或仅包含无法避免的说明。
- Create in temp: `source-facts.txt` — 从代码和仓库文档提取的事实、状态与文件出处。
- Create in temp: `rendered/` — 最终逐页 PNG 渲染结果。

### Task 1: 加载演示运行时并审计模板

**Files:**
- Read: `C:/Users/61004/.codex/plugins/cache/openai-curated-remote/openai-templates/0.1.0/skills/artifact-template-business-review/assets/reference.pptx`
- Create in temp: `template-audit.txt`
- Create in temp: `template-frame-map.json`
- Create in temp: `deviation-log.txt`

**Interfaces:**
- Consumes: Business Review `reference.pptx`。
- Produces: 可由生成脚本读取的模板 frame/placeholder 映射。

- [ ] **Step 1: 加载 Codex bundled workspace dependencies**

调用 `codex_app__load_workspace_dependencies`，记录 Node、Python、artifact-tool 和演示脚本路径。

- [ ] **Step 2: 创建系统临时工作目录**

Run: `New-Item -ItemType Directory -Force "$env:TEMP\ipad-sdk-manager-deck"`

Expected: 返回临时目录对象，仓库工作树无新增中间文件。

- [ ] **Step 3: 使用 presentation inspect 脚本审计所有源幻灯片**

Run: 使用运行时返回的模板检查脚本对 `reference.pptx` 执行全页检查，并将文本结果写入临时目录 `template-audit.txt`。

Expected: 审计包含每一页尺寸、对象、占位符、字体、颜色和可复用用途。

- [ ] **Step 4: 建立模板 frame map**

写入 `template-frame-map.json`，至少定义 `cover`、`section`、`title_content`、`two_column`、`table`、`closing` 六类语义页面到模板页和目标对象的映射。

- [ ] **Step 5: 检查模板偏差日志初始状态**

写入 `deviation-log.txt`，首行固定为 `No deviations before authoring.`。

### Task 2: 提取并校验仓库事实

**Files:**
- Read: `ipa_sdk_pc/include/ipa.h`
- Read: `ipa_sdk_pc/include/ipa_core.h`
- Read: `ipa_sdk_pc/include/typedefs.h`
- Read: `ipa_sdk_pc/include/es10_typedefs.h`
- Read: `ipad_host_app/include/ipad_wrapper.h`
- Read: `ipad_host_app/src/sdk_wrapper/ipad_wrapper.c`
- Read: `ipad_host_app/src/gui/gui_main.c`
- Read: `ipad_host_app/include/app_api_definitions.h`
- Read: `README.md`, `PROJECT_STRUCTURE.md`, `DEVELOPMENT_SUMMARY.md`
- Read: `ipad_host_app/docs/*.md`, `RELEASE_NOTES_v*.md`
- Read: `CMakeLists.txt`, `ipa_sdk_pc/CMakeLists.txt`, `ipad_host_app/CMakeLists.txt`
- Read: `quickstart.sh`, `build_sdk.sh`, `build_all.sh`
- Create in temp: `source-facts.txt`

**Interfaces:**
- Consumes: 当前代码和文档。
- Produces: 每条能力、API、模块、兼容性、部署步骤和风险的事实记录及状态标签。

- [ ] **Step 1: 提取公开 SDK 和 Wrapper 接口签名**

Run: `rg -n "^(ErrCode|int|void|bool|const char\*) +(ipa_|ipad_wrapper_)" ipa_sdk_pc/include ipad_host_app/include ipad_host_app/src/sdk_wrapper`

Expected: 输出所有演示稿需要覆盖的 SDK/Wrapper 入口。

- [ ] **Step 2: 校验 GUI 实际分发路径**

Run: `rg -n "ipad_wrapper_|strcmp|API_CATEGORY" ipad_host_app/src/gui/gui_main.c ipad_host_app/include/app_api_definitions.h`

Expected: 可区分 GUI 已连接能力和仅声明能力。

- [ ] **Step 3: 校验占位实现和文档偏差**

Run: `rg -n "eNotImpl|NotImpl|TODO|profile_(download|enable|disable|delete)" ipad_host_app ipa_sdk_pc README.md RELEASE_NOTES_v1.1.0.md DEVELOPMENT_SUMMARY.md`

Expected: 明确 Profile 管理占位项及发布说明与当前代码的差异。

- [ ] **Step 4: 校验构建选项和部署脚本**

Run: `rg -n "option\(|ENABLE_|SGP22|SGP32|PCSC|MQTT|LWM2M|HTTP|apt|cmake|make|build" CMakeLists.txt ipa_sdk_pc/CMakeLists.txt ipad_host_app/CMakeLists.txt quickstart.sh build_sdk.sh build_all.sh`

Expected: 得到默认构建能力、依赖和一键部署执行顺序。

- [ ] **Step 5: 汇总事实清单**

将结果写入 `source-facts.txt`，每项使用 `FACT | STATUS | SOURCE | NOTE` 格式；不得出现无出处的性能、规模或兼容性数字。

### Task 3: 建立页级内容模型

**Files:**
- Create: `tools/presentation/ipad_deck_content.mjs`

**Interfaces:**
- Consumes: `source-facts.txt` 和已确认设计说明。
- Produces: `export const slides`，每项包含 `id`、`section`、`title`、`audiences`、`layout`、`statusLegend` 和 `content`。

- [ ] **Step 1: 定义页面数据契约**

```js
export const slides = [
  {
    id: "A01",
    section: "定位与全景",
    title: "IPAd 将 eUICC 底层能力封装为可集成、可运维的桌面管理工具",
    audiences: ["管理", "客户", "研发"],
    layout: "cover",
    statusLegend: false,
    content: {}
  }
];
```

- [ ] **Step 2: 填充 A–F 六章约 40–50 页内容**

每页标题必须是结论或清晰主题；正文每页控制为一个核心观点，技术细节移入矩阵、图或附录。

- [ ] **Step 3: 加入三类裁剪路径**

定义 `managementCut`、`customerCut`、`engineeringCut` 三个页 ID 数组，并保证每套都含封面、摘要、相关正文和总结。

- [ ] **Step 4: 自查事实状态标签**

Run: `rg -n "已实现并接入|接入不完整|占位|未验证|建议演进" tools/presentation/ipad_deck_content.mjs`

Expected: 能力与架构页均使用统一状态词，不使用“全部完成”等未经证明的表述。

### Task 4: 实现模板样式和演示稿生成器

**Files:**
- Create: `tools/presentation/ipad_deck_styles.mjs`
- Create: `tools/presentation/build_ipad_sdk_manager_deck.mjs`

**Interfaces:**
- Consumes: `slides`、模板 frame map 和 `reference.pptx`。
- Produces: `outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx`。

- [ ] **Step 1: 定义颜色、字体和状态样式**

```js
export const palette = {
  cobalt: "2457D6",
  ink: "14171A",
  gray: "6B7280",
  pale: "F4F6F9",
  warning: "D97706",
  white: "FFFFFF"
};

export const statusStyles = {
  integrated: { fill: palette.cobalt, line: palette.cobalt },
  partial: { fill: palette.white, line: palette.cobalt },
  placeholder: { fill: "E5E7EB", line: "9CA3AF" },
  risk: { fill: "FFF7ED", line: palette.warning },
  proposed: { fill: palette.white, line: palette.gray, dash: "dash" }
};
```

- [ ] **Step 2: 实现模板导入与目标对象编辑**

生成器必须导入 `reference.pptx`，复制映射页面，再编辑继承的标题、正文、页码和受众标签对象；不得用整页白色矩形覆盖模板。

- [ ] **Step 3: 实现架构、调用链、时序和矩阵布局函数**

至少提供 `renderLayeredArchitecture`、`renderCallFlow`、`renderSequence`、`renderMatrix`、`renderAudienceTags`，所有坐标和字号从模板样式派生。

- [ ] **Step 4: 导出 PPTX**

Run: 使用 bundled Node 执行 `tools/presentation/build_ipad_sdk_manager_deck.mjs`。

Expected: 生成约 40–50 页的 `outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx`，无脚本错误。

- [ ] **Step 5: 提交生成器和内容模型**

Run: `git add tools/presentation/ipad_deck_content.mjs tools/presentation/ipad_deck_styles.mjs tools/presentation/build_ipad_sdk_manager_deck.mjs && git commit -m "feat: generate IPAd SDK manager presentation"`

Expected: 提交仅包含演示稿生成源文件。

### Task 5: 渲染并逐页视觉检查

**Files:**
- Read: `outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx`
- Create in temp: `rendered/*.png`

**Interfaces:**
- Consumes: 首轮 PPTX。
- Produces: 逐页渲染图和修正后的 PPTX。

- [ ] **Step 1: 渲染全部幻灯片**

Run: 使用 bundled presentation render 脚本将 PPTX 输出到临时目录 `rendered/`。

Expected: PNG 数量与 PPTX 页数一致。

- [ ] **Step 2: 逐页检查**

检查标题截断、文本溢出、对象遮挡、表格密度、状态颜色、受众标签、模板元素和章节连续性。

- [ ] **Step 3: 修正版式问题**

只修改 `ipad_deck_content.mjs`、`ipad_deck_styles.mjs` 或生成器中的目标页面定义，然后重新生成和渲染；不得直接在成品 PPTX 上进行不可复现的手工修补。

- [ ] **Step 4: 更新偏差日志**

若存在无法避免的模板偏差，在 `deviation-log.txt` 中记录页面、原因和影响；否则写入 `No template deviations in final deck.`。

### Task 6: 自动化结构和模板一致性检查

**Files:**
- Read: `outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx`
- Read in temp: `template-frame-map.json`, `deviation-log.txt`

**Interfaces:**
- Consumes: 视觉检查后的 PPTX。
- Produces: 通过全部 QA 的最终 PPTX。

- [ ] **Step 1: 运行 slides_test.py**

Run: `python <bundled-slides-test-path> outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx`

Expected: 无越界、重叠或损坏对象错误。

- [ ] **Step 2: 运行模板一致性检查**

Run: `python <bundled-check-template-fidelity-path> --template <reference.pptx> --candidate outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx --frame-map <temp>/template-frame-map.json --deviation-log <temp>/deviation-log.txt`

Expected: 检查通过，所有偏差均有记录且不影响模板识别度。

- [ ] **Step 3: 检查 PPTX 结构**

Run: 使用 inspect 脚本确认页数、16:9 尺寸、标题覆盖率、对象可编辑性和无空白页。

Expected: 约 40–50 页，所有页面有标题，架构和表格均为可编辑原生对象。

- [ ] **Step 4: 最终打开抽查关键页**

至少检查封面、执行摘要、SDK 能力地图、API 调用链、Manager 分层架构、兼容性矩阵、一键部署、风险路线图和 API 附录。

### Task 7: 最终交付与提交

**Files:**
- Create/Modify: `outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx`

**Interfaces:**
- Consumes: QA 通过的最终 PPTX。
- Produces: 用户可下载、可编辑、可裁剪的交付文件。

- [ ] **Step 1: 确认最终文件存在且非空**

Run: `Get-Item outputs\IPAd_SDK_Manager_Architecture_and_Usage.pptx | Select-Object FullName,Length,LastWriteTime`

Expected: 文件存在，长度大于 0，时间为本次生成时间。

- [ ] **Step 2: 确认工作树只包含预期文件**

Run: `git status --short`

Expected: 不修改 `install_wsl.ps1` 和 `wsl-install.log`，不包含临时审计或渲染文件。

- [ ] **Step 3: 提交最终 PPTX**

Run: `git add outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx && git commit -m "docs: add IPAd SDK manager presentation"`

Expected: 最终演示稿形成独立提交。

- [ ] **Step 4: 交付链接**

最终回复只提供 `outputs/IPAd_SDK_Manager_Architecture_and_Usage.pptx` 的独立可点击链接。
