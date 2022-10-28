function sidebarGuide() {
  return [
    {
      text: 'Introduction',
      items: [
        { text: 'Prelude', link: '/prerequisites' },
        { text: 'Overview', link: '/overview' },
        { text: 'Resources', link: '/resources' },
      ],
    },
    {
      text: 'User Space Interface',
      items: [
        { text: 'Instruction Set', link: '/user/spec' },
        { text: 'The Syscall', link: '/user/syscall' },
        { text: 'Learn From Libbpf', link: '/user/libbpf' },
      ]
    },
    {
      text: 'Kernel Implementation',
      items: [
        { text: 'Syscall Entrance', link: '/impl/syscall' },
        { text: 'eBPF Verifier', link: '/impl/verifier' },
      ],
    },
  ]
}

function footerLicense() {
  return {
    message: 'Released under a <a href="https://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>',
    copyright: '<a rel="license" style="display: inline-block" href="https://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="height: 2em" src="https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/by-sa.svg" /></a>',
  }
}

export default {
  title: 'eBPF Hitchhiking',
  description: 'Absolutely not a guide to the galaxy.',
  base: '/ebpf-analyzer/',
  lang: 'en',
  lastUpdated: true,
  themeConfig: {
    outline: 'deep',
    editLink: {
      pattern: 'https://github.com/yesh0/ebpf-analyzer/blob/docs/docs/:path',
      text: 'Page source',
    },
    lastUpdatedText: 'Last updated at',
    socialLinks: [
      { icon: 'github', link: 'https://github.com/yesh0/ebpf-analyzer/tree/docs' },
    ],
    footer: footerLicense(),
    sidebar: {
      '/': sidebarGuide(),
    },
  },
}
