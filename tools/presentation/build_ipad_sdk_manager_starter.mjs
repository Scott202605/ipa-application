import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { slides, sourceSlideForType } from "./ipad_deck_content.mjs";

const runtimeRoot = "C:/Users/61004/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/@oai/artifact-tool";
const artifactTool = await import(pathToFileURL(path.join(runtimeRoot, "dist/artifact_tool.mjs")).href);
const { FileBlob, PresentationFile } = artifactTool;

const repoRoot = path.resolve(process.cwd());
const templatePath = "C:/Users/61004/.codex/plugins/cache/openai-curated-remote/openai-templates/0.1.0/skills/artifact-template-business-review/assets/reference.pptx";
const tempRoot = path.join(process.env.TEMP || "C:/tmp", "ipad-sdk-manager-deck");
const starterPath = path.join(tempRoot, "ipad-sdk-manager-starter.pptx");
const contentPath = path.join(tempRoot, "ipad-deck-content.json");
const mapPath = path.join(tempRoot, "template-frame-map.json");
const auditPath = path.join(tempRoot, "template-audit.txt");
const deviationPath = path.join(tempRoot, "deviation-log.txt");

await fs.mkdir(tempRoot, { recursive: true });
const presentation = await PresentationFile.importPptx(await FileBlob.load(templatePath));
const originals = Array.isArray(presentation.slides?.items)
  ? [...presentation.slides.items]
  : Array.from({ length: presentation.slides.count }, (_, index) => presentation.slides.getItem(index));

const outputSlides = [];
const duplicates = [];
for (let index = 0; index < slides.length; index += 1) {
  const definition = slides[index];
  const sourceSlide = sourceSlideForType[definition.type] || 7;
  const duplicate = originals[sourceSlide - 1].duplicate();
  duplicates.push(duplicate);
  outputSlides.push({
    outputSlide: index + 1,
    sourceSlide,
    narrativeRole: `${definition.section}: ${definition.title}`,
    reuseMode: "duplicate-slide",
    editTargets: ["title", "body", "footer", "slideNumber", "audienceTag"],
  });
}

for (const slide of originals) slide.delete();
for (let index = 0; index < duplicates.length; index += 1) duplicates[index].moveTo(index);

const output = await PresentationFile.exportPptx(presentation);
await output.save(starterPath);
await fs.writeFile(contentPath, `${JSON.stringify(slides, null, 2)}\n`, "utf8");
await fs.writeFile(mapPath, `${JSON.stringify({ template: templatePath, outputSlides }, null, 2)}\n`, "utf8");
await fs.writeFile(auditPath, [
  "Business Review template audit",
  "Source slides: 14",
  "Slide size: 960 x 540 points (16:9)",
  "Primary palette: cobalt blue, white, black, light gray",
  "Reusable layouts: cover, agenda, executive summary, card grid, three callouts, two-column, table, timeline, closing",
  "Typography: inherited Aptos/Arial-compatible Office theme fonts",
  "Authoring rule: duplicate mapped source slides; preserve theme/master; replace content with editable native shapes.",
].join("\n") + "\n", "utf8");
await fs.writeFile(deviationPath, "PowerPoint used as the compatible visual renderer because the bundled Vulkan renderer is unavailable on this host.\n", "utf8");

console.log(JSON.stringify({ repoRoot, starterPath, contentPath, mapPath, auditPath, deviationPath, slideCount: slides.length }, null, 2));
