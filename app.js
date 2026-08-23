const treeEl = document.getElementById("tree");
const toc = document.getElementById("toc");
const q = document.getElementById("q");
const sheet = document.getElementById("sheet");

function countLeaves(node) {
  if (!node.children) return 1;
  return node.children.reduce((s, c) => s + countLeaves(c), 0);
}

function render() {
  const cats = TREE.children;
  document.getElementById("cats").textContent = cats.length;
  document.getElementById("count").textContent = countLeaves(TREE) - 1 - cats.length;

  treeEl.innerHTML = `<div class="root-title">◈ Arbor</div>`;
  toc.innerHTML = "";

  cats.forEach((cat) => {
    const a = document.createElement("a");
    a.href = `#cat-${cat.id}`;
    a.textContent = `${cat.name} · ${cat.children.length}`;
    toc.appendChild(a);

    const block = document.createElement("div");
    block.className = "branch-block";
    block.id = `cat-${cat.id}`;

    const head = document.createElement("button");
    head.className = "cat";
    head.innerHTML = `<span>✱ ${cat.name}</span><small>${cat.children.length}</small>`;
    head.addEventListener("click", () => {
      leaves.style.display = leaves.style.display === "none" ? "grid" : "none";
    });

    const leaves = document.createElement("div");
    leaves.className = "leaves";

    cat.children.forEach((tool) => {
      const card = document.createElement("article");
      card.className = "leaf";
      card.dataset.name = tool.name.toLowerCase();
      card.dataset.desc = (tool.desc || "").toLowerCase();
      card.dataset.cat = cat.name.toLowerCase();
      card.innerHTML = `<h3>${tool.name}</h3><p>${tool.desc}</p>`;
      card.addEventListener("click", () => openSheet(tool, cat.name));
      leaves.appendChild(card);
    });

    block.appendChild(head);
    block.appendChild(leaves);
    treeEl.appendChild(block);
  });
}

function openSheet(tool, cat) {
  document.getElementById("s-title").textContent = tool.name;
  document.getElementById("s-cat").textContent = cat;
  document.getElementById("s-desc").textContent = tool.desc;
  const link = document.getElementById("s-link");
  link.href = tool.url;
  sheet.classList.remove("hidden");
}

document.getElementById("close").onclick = () => sheet.classList.add("hidden");

q.addEventListener("input", () => {
  const v = q.value.trim().toLowerCase();
  document.querySelectorAll(".leaf").forEach((el) => {
    const hit = !v || el.dataset.name.includes(v) || el.dataset.desc.includes(v) || el.dataset.cat.includes(v);
    el.classList.toggle("dim", !hit);
  });
});

render();