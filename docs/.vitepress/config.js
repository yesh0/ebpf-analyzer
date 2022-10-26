export default {
  title: 'eBPF Hitchhiking',
  description: 'Absolutely not a guide to the galaxy.',
  base: '/ebpf-analyzer/',
  themeConfig: {
    editLink: {
      pattern: 'https://github.com/yesh0/ebpf-analyzer/blob/docs/docs/:path',
      text: 'Page source',
    },
    lastUpdatedText: 'Last updated at',
    socialLinks: [
      { icon: 'github', link: 'https://github.com/yesh0/ebpf-analyzer/tree/docs' },
    ],
    sidebar: [
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
          { text: 'The Syscall', link: '/user/syscall' },
          { text: 'Learn From Libbpf', link: '/user/libbpf' },
        ]
      },
    ],
  },
}
