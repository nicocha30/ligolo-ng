import * as React from "react";
import { Link } from "@heroui/react";
import { Navbar } from "@/components/navbar";

export default function DefaultLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="relative flex flex-col h-screen">
      <Navbar />
      <main className="container mx-auto max-w-7xl px-6 flex-grow">
        {children}
      </main>
      <footer className="w-full flex items-center justify-center py-3">
        <Link
          isExternal
          className="flex items-center gap-1 text-current"
          href="https://github.com/allsmog/ligolo-ng-relay"
          title="Ligolo-ng Relay homepage"
        >
          <span className="text-default-600">Ligolo-ng Relay WebUI -</span>
          <p className="text-primary">Nicocha30 & L&#39;Ami du Raisin</p>
        </Link>
      </footer>
    </div>
  );
}
