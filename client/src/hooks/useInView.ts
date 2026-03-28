import { useEffect, useRef, useState } from "react";

/**
 * Custom hook that uses IntersectionObserver to detect when an element
 * enters the viewport. Once triggered, it stays "in view" permanently
 * (one-shot animation trigger).
 */
export function useInView(options?: IntersectionObserverInit) {
  const ref = useRef<HTMLDivElement>(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInView(true);
          observer.unobserve(el); // one-shot: stop observing after first trigger
        }
      },
      { threshold: 0.15, ...options }
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return { ref, inView };
}
