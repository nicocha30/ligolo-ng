export type SiteConfig = typeof siteConfig;

export const siteConfig = {
  name: "Ligolo-ng Relay web",
  description: "An advanced, yet simple, tunneling tool that uses TUN interfaces.",
  navItems: [
    {
      label: "Agents",
      href: "/agents"
    },
    {
      label: "Relay",
      href: "/relay"
    },
    {
      label: "Interfaces",
      href: "/interfaces"
    },
    {
      label: "Listeners",
      href: "/listeners"
    }
  ],
  links: {
    github: "https://github.com/allsmog/ligolo-ng-relay",
    twitter: "https://twitter.com/nicocha30",
    docs: "https://github.com/allsmog/ligolo-ng-relay/blob/master/ENHANCEMENTS.md",
    sponsor: "https://github.com/sponsors/nicocha30"
  }
};
