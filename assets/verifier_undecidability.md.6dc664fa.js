import{_ as s,c as a,o as n,a as l}from"./app.3775c9dd.js";const C=JSON.parse('{"title":"Undecidable Programs","description":"","frontmatter":{},"headers":[{"level":2,"title":"Failing snippets","slug":"failing-snippets","link":"#failing-snippets","children":[]}],"relativePath":"verifier/undecidability.md","lastUpdated":1672991337000}'),p={name:"verifier/undecidability.md"},o=l(`<h1 id="undecidable-programs" tabindex="-1">Undecidable Programs <a class="header-anchor" href="#undecidable-programs" aria-hidden="true">#</a></h1><p>eBPF is not <a href="https://en.wikipedia.org/wiki/Turing_completeness" target="_blank" rel="noreferrer">Turing-complete</a>, nor can any verifier validate a Turing-complete language: the <a href="https://en.wikipedia.org/wiki/Halting_problem" target="_blank" rel="noreferrer">halting problem</a> is undecidable.</p><p>Therefore, the verifier can reject totally regular programs, requiring the programmer to adjust to it.</p><h2 id="failing-snippets" tabindex="-1">Failing snippets <a class="header-anchor" href="#failing-snippets" aria-hidden="true">#</a></h2><p>Some snippets that failed verification on Linux 5.19 are listed below.</p><p><code>data_end</code> and <code>data</code> marks the packet content received by an XDP filter.</p><ul><li><p>The pointer <code>data</code> is reported as out of bound.</p><div class="language-c"><button title="Copy Code" class="copy"></button><span class="lang">c</span><pre class="shiki"><code><span class="line"><span style="color:#89DDFF;">for</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">(</span><span style="color:#C792EA;">int</span><span style="color:#A6ACCD;"> i </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#F78C6C;">0</span><span style="color:#89DDFF;">;</span><span style="color:#A6ACCD;"> i </span><span style="color:#89DDFF;">&lt;</span><span style="color:#A6ACCD;"> data_end </span><span style="color:#89DDFF;">-</span><span style="color:#A6ACCD;"> data</span><span style="color:#89DDFF;">;</span><span style="color:#A6ACCD;"> i</span><span style="color:#89DDFF;">++)</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">{</span></span>
<span class="line"><span style="color:#F07178;">    </span><span style="color:#89DDFF;">if</span><span style="color:#F07178;"> </span><span style="color:#89DDFF;">(((</span><span style="color:#C792EA;">char</span><span style="color:#F07178;"> </span><span style="color:#89DDFF;">*)</span><span style="color:#F07178;"> data</span><span style="color:#89DDFF;">)[</span><span style="color:#F07178;">i</span><span style="color:#89DDFF;">]</span><span style="color:#F07178;"> </span><span style="color:#89DDFF;">==</span><span style="color:#F07178;"> </span><span style="color:#89DDFF;">-</span><span style="color:#F78C6C;">1</span><span style="color:#89DDFF;">)</span><span style="color:#F07178;"> </span><span style="color:#89DDFF;">{</span></span>
<span class="line"><span style="color:#F07178;">        </span><span style="color:#89DDFF;">return</span><span style="color:#F07178;"> XDP_PASS</span><span style="color:#89DDFF;">;</span></span>
<span class="line"><span style="color:#F07178;">    </span><span style="color:#89DDFF;">}</span></span>
<span class="line"><span style="color:#89DDFF;">}</span></span>
<span class="line"></span></code></pre></div></li><li><p>The pointer <code>p</code> is reported as out of bound.</p><div class="language-c"><button title="Copy Code" class="copy"></button><span class="lang">c</span><pre class="shiki"><code><span class="line"><span style="color:#89DDFF;">for</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">(</span><span style="color:#C792EA;">char</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">*</span><span style="color:#A6ACCD;">p </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> data</span><span style="color:#89DDFF;">;</span><span style="color:#A6ACCD;"> p </span><span style="color:#89DDFF;">&lt;</span><span style="color:#A6ACCD;"> data_end</span><span style="color:#89DDFF;">;</span><span style="color:#A6ACCD;"> p</span><span style="color:#89DDFF;">++)</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">{</span></span>
<span class="line"><span style="color:#F07178;">    </span><span style="color:#89DDFF;">if</span><span style="color:#F07178;"> </span><span style="color:#89DDFF;">(*</span><span style="color:#F07178;">p </span><span style="color:#89DDFF;">==</span><span style="color:#F07178;"> </span><span style="color:#89DDFF;">-</span><span style="color:#F78C6C;">1</span><span style="color:#89DDFF;">)</span><span style="color:#F07178;"> </span><span style="color:#89DDFF;">{</span></span>
<span class="line"><span style="color:#F07178;">        </span><span style="color:#89DDFF;">return</span><span style="color:#F07178;"> XDP_PASS</span><span style="color:#89DDFF;">;</span></span>
<span class="line"><span style="color:#F07178;">    </span><span style="color:#89DDFF;">}</span></span>
<span class="line"><span style="color:#89DDFF;">}</span></span>
<span class="line"></span></code></pre></div></li><li><p>The loop is reported as &quot;infinite&quot; with <code>clang -O0</code>, possibly due to misaligned spilled values.</p><div class="language-c"><button title="Copy Code" class="copy"></button><span class="lang">c</span><pre class="shiki"><code><span class="line"><span style="color:#C792EA;">int</span><span style="color:#A6ACCD;"> result </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#F78C6C;">0</span><span style="color:#89DDFF;">;</span></span>
<span class="line"><span style="color:#89DDFF;">for</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">(</span><span style="color:#C792EA;">int</span><span style="color:#A6ACCD;"> i </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#F78C6C;">0</span><span style="color:#89DDFF;">;</span><span style="color:#A6ACCD;"> i </span><span style="color:#89DDFF;">&lt;</span><span style="color:#A6ACCD;"> </span><span style="color:#F78C6C;">0x10</span><span style="color:#89DDFF;">;</span><span style="color:#A6ACCD;"> i</span><span style="color:#89DDFF;">++)</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">{</span></span>
<span class="line"><span style="color:#F07178;">    result </span><span style="color:#89DDFF;">+=</span><span style="color:#F07178;"> i</span><span style="color:#89DDFF;">;</span></span>
<span class="line"><span style="color:#89DDFF;">}</span></span>
<span class="line"></span></code></pre></div><p>I managed to reproduce this with the following eBPF assembly:</p><div class="language-"><button title="Copy Code" class="copy"></button><span class="lang"></span><pre class="shiki"><code><span class="line"><span style="color:#A6ACCD;">xdp_prog_simple:</span></span>
<span class="line"><span style="color:#A6ACCD;">    r1 = 0</span></span>
<span class="line"><span style="color:#A6ACCD;">    *(u32 *)(r10 - 4) = r1     # Spilled</span></span>
<span class="line"><span style="color:#A6ACCD;">    goto LBB0_1</span></span>
<span class="line"><span style="color:#A6ACCD;">LBB0_1:</span></span>
<span class="line"><span style="color:#A6ACCD;">    r1 = *(u32 *)(r10 - 4)     # Restore</span></span>
<span class="line"><span style="color:#A6ACCD;">    if r1 s&gt; 32767 goto LBB0_2</span></span>
<span class="line"><span style="color:#A6ACCD;">    r1 += 1</span></span>
<span class="line"><span style="color:#A6ACCD;">    *(u32 *)(r10 - 4) = r1     # Spilled</span></span>
<span class="line"><span style="color:#A6ACCD;">    goto LBB0_1</span></span>
<span class="line"><span style="color:#A6ACCD;">LBB0_2:</span></span>
<span class="line"><span style="color:#A6ACCD;">    r0 = r1</span></span>
<span class="line"><span style="color:#A6ACCD;">    exit</span></span>
<span class="line"><span style="color:#A6ACCD;"></span></span></code></pre></div><p>It works fine if the spilled value is 64-bit aligned.</p></li></ul>`,7),e=[o];function t(r,c,i,D,y,F){return n(),a("div",null,e)}const A=s(p,[["render",t]]);export{C as __pageData,A as default};
