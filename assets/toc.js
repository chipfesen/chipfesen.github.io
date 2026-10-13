/* 从正文标题自动生成左侧目录。
   不需要在 Markdown 里写任何标记，标题的层级关系原样映射成目录的嵌套层级。 */
(function () {
  var content = document.querySelector('.post-content');
  var listEl = document.getElementById('toc-list');
  if (!content || !listEl) return;

  var headings = [].slice.call(content.querySelectorAll('h1, h2, h3, h4, h5, h6'));
  if (headings.length < 2) return;

  var DEFAULT_DEPTH = 4;      // 默认展开到第几级
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

  var links = {};
  [].forEach.call(listEl.querySelectorAll('a'), function (a) {
    links[decodeURIComponent(a.getAttribute('href').slice(1))] = a;
  });

  /* 关键：缓存每个标题相对文档的位置。
     绝不能每帧对全部标题调用 getBoundingClientRect —— 长文有几百个标题，
     那等于每帧触发几百次强制同步布局，滚动会明显卡顿/抽搐。
     页面布局本身是稳定的（图片都写了 width/height 预留高度），所以量一次就够。 */
  var tops = [];
  function measure() {
    var sy = window.pageYOffset;
    tops = [];
    for (var i = 0; i < headings.length; i++) {
      tops.push(headings[i].getBoundingClientRect().top + sy);
    }
  }
  measure();

  var current = null;

  function highlight() {
    var y = window.pageYOffset + 100;
    // 二分查找：最后一个位置 <= y 的标题即当前章节，纯数值比较，不碰 DOM
    var lo = 0, hi = tops.length - 1, idx = -1;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      if (tops[mid] <= y) { idx = mid; lo = mid + 1; } else { hi = mid - 1; }
    }
    var best = idx >= 0 ? headings[idx] : null;
    if (!best || best === current) return;

    if (current && links[current.id]) links[current.id].classList.remove('active');
    current = best;

    var a = links[current.id];
    if (!a) return;
    a.classList.add('active');

    // 展开祖先节点，保证当前项可见
    var p = a.parentNode.parentNode;
    while (p && p !== listEl) {
      if (p.tagName === 'UL' && p.style.display === 'none') p.style.display = '';
      p = p.parentNode;
    }

    var box = listEl.getBoundingClientRect(), ab = a.getBoundingClientRect();
    if (ab.top < box.top || ab.bottom > box.bottom) {
      listEl.scrollTop += ab.top - box.top - box.height / 2;
    }
  }

  var ticking = false;
  window.addEventListener('scroll', function () {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () { highlight(); ticking = false; });
  }, { passive: true });

  // 视口变化或图片加载完成后重新量一次
  var rtimer;
  window.addEventListener('resize', function () {
    clearTimeout(rtimer);
    rtimer = setTimeout(function () { measure(); current = null; highlight(); }, 200);
  });
  window.addEventListener('load', function () {
    measure();
    current = null;
    highlight();
  });

  highlight();
})();
