"use client";
import { useState } from 'react';
import { Navbar } from '@/app/components';
import { NavLink } from '@/app/components/Navbar';
import { useSession } from '@/app/components/SessionProvider';
import { faCalendar, faGear, faRightToBracket, faBrightness, faMoon, faUser, faFileExcel, faSquarePlus } from '@awesome.me/kit-10a739193a/icons/classic/light';
import { faPray, faHandsPraying } from '@awesome.me/kit-10a739193a/icons/classic/solid';

const PageDefaults = () => {
  const session = useSession();
  // const { user, isAuthenticated } = useUser();
  // const { theme, toggleTheme } = useTheme();
  const [sOpen, setSOpen] = useState<boolean | undefined>();
  const [aOpen, setAOpen] = useState<boolean | undefined>();

  const navLinks: NavLink[] = [
    {
      variant: "link",
      label: "Calendar",
      icon: faCalendar,
      link: "/",
      action: null
    },
    {
      variant: "link",
      label: "Create",
      icon: faSquarePlus,
      link: "/create",
      action: null
    },
    {
      variant: "link",
      label: "Health Assessment",
      icon: faFileExcel,
      link: "/ha",
      action: null
    },
    {
      variant: "link",
      label: "Prayer Wall",
      icon: faPray,
      link: "/prayerwall",
      action: null
    },
    {
      variant: "spacer",
      label: null,
      icon: null,
      link: null,
      action: null
    },
    {
      variant: "link",
      // label: theme === "dark" ? "Light Mode" : "Dark Mode",
      // icon: theme === "dark" ? faBrightness : faMoon,
      label: "dark",
      icon: faBrightness,
      link: null,
      action: () => console.log('toggle theme'),
    },
    {
      variant: "link",
      label: "Settings",
      icon: faGear,
      link: null,
      action: () => setSOpen(true)
    }
    // {
    //   variant: "link",
    //   label: isAuthenticated ? "Account" : "Login",
    //   // icon: faRightToBracket,
    //   icon: isAuthenticated ? faUser : faRightToBracket,
    //   link: isAuthenticated ? null : "/login",
    //   action: isAuthenticated ? () => setAOpen(true) : null,
    // }
  ];

  return (
    <>
      {/* <SettingsPopup open={sOpen} setOpen={setSOpen} /> */}
      {/* <AccountPopup open={aOpen} setOpen={setAOpen} /> */}
      <Navbar navLinks={navLinks} session={session} />
    </>
  );
};

export default PageDefaults;
