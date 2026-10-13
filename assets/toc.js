/* 从正文标题自动生成左侧目录。
   不需要在 Markdown 里写任何标记，标题的层级关系原样映射成目录的嵌套层级。 */
(function () {
  var content = document.querySelector('.post-content');
  var listEl = document.getElementById('toc-list');
  if (!content || !listEl) return;

  var headings = [].slice.call(content.querySelectorAll('h1, h2, h3, h4, h5, h6'));
  if (headings.length < 2) return;

  var DEFAULT_DEPTH = 4;      // 默认展开到第几级（相对正文最小标题层级）
  var root = { level: 0, children: [] };
  var stack = [root];

  headings.forEach(function (h, i) {
    if (!h.id) h.id = 'h-' + i;
    var level = parseInt(h.tagName.substring(1), 10);
    var node = { level: level, children: [], el: h, id: h.id, text: h.textContent.trim() };
    while (stack.length > 1 && stack[stack.length - 1].level >= level) stack.pop();
    stack[stack.length - 1].children.push(node);
    stack.push(node);
  });

  function render(nodes, depth) {
    var ul = document.createElement('ul');
    ul.className = 'toc-depth-' + depth;
    nodes.forEach(function (n) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = '#' + n.id;
      a.textContent = n.text;
      li.appendChild(a);
      if (n.children.length) {
        li.className = 'has-children';
        var sub = render(n.children, depth + 1);
        if (depth >= DEFAULT_DEPTH) sub.style.display = 'none';
        li.appendChild(sub);
      }
      ul.appendChild(li);
    });
    return ul;
  }

  listEl.appendChild(render(root.children, 1));

  // 折叠 / 展开
  listEl.addEventListener('click', function (e) {
    var a = e.target.closest('a');
    if (!a) return;
    var li = a.parentNode;
    var sub = li.querySelector('ul');
    if (sub && !e.ctrlKey && !e.metaKey) {
      sub.style.display = sub.style.display === 'none' ? '' : 'none';
      e.preventDefault();
    } else if (sub) {
      sub.style.display = '';
    }
  });

  var toggle = document.getElementById('toc-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var hide = listEl.style.display !== 'none';
      listEl.style.display = hide ? 'none' : '';
      toggle.textContent = hide ? '+' : '−';
    });
  }

  // 滚动到哪一节，就在目录里高亮哪一条
  var links = {};
  [].forEach.call(listEl.querySelectorAll('a'), function (a) {
    links[decodeURIComponent(a.getAttribute('href').slice(1))] = a;
  });

  var current = null;
  function highlight() {
    var best = null;
    for (var i = 0; i < headings.length; i++) {
      if (headings[i].getBoundingClientRect().top <= 100) best = headings[i];
      else break;
    }
    if (!best || best === current) return;
    if (current && links[current.id]) links[current.id].classList.remove('active');
    current = best;
    var a = links[current.id];
    if (a) {
      a.classList.add('active');
      // 展开祖先节点，让高亮项可见
      var p = a.parentNode.parentNode;
      while (p && p !== listEl) {
        if (p.tagName === 'UL') p.style.display = '';
        p = p.parentNode;
      }
      var box = listEl.getBoundingClientRect(), ab = a.getBoundingClientRect();
      if (ab.top < box.top || ab.bottom > box.bottom) {
        listEl.scrollTop += ab.top - box.top - box.height / 2;
      }
    }
  }

  var ticking = false;
  window.addEventListener('scroll', function () {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () { highlight(); ticking = false; });
  }, { passive: true });
  highlight();
})();
