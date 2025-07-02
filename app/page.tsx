"use client";
import Link from "next/link";
import { useEffect } from "react";
import axios from "axios";

export default function Home() {
  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const response = await axios.get('/api/events?startDate=2025&endDate=2026');
        console.log('Events data:', response.data);
      } catch (error) {
        console.error('Error fetching events:', error);
      }
    };

    fetchEvents();
  }, []);

  return (
    <div className="p-4 text-xl">
      <div className="flex flex-col gap-4">
        <a href="/api/login?returnTo=/create" className="text-blue-600 hover:text-blue-800 underline">Login</a>
        <Link href="/api/logout">Logout</Link>
        <Link href="/events">Events</Link>
      </div>
    </div>
  );
}
