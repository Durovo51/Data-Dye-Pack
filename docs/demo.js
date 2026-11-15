const demoFrame = document.getElementById("project-video");
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

if (demoFrame && "IntersectionObserver" in window && !reducedMotion.matches) {
  const threshold = 0.55;
  let inView = false;
  let apiRequested = false;
  let demoPlayer;

  function startDemo() {
    if (!demoPlayer || !inView || document.hidden || reducedMotion.matches) return;

    demoObserver.disconnect();
    document.removeEventListener("visibilitychange", startDemo);
    const state = demoPlayer.getPlayerState();
    if (state === YT.PlayerState.UNSTARTED || state === YT.PlayerState.CUED) {
      demoPlayer.mute();
      demoPlayer.playVideo();
    }
  }

  const demoObserver = new IntersectionObserver(([entry]) => {
    inView = entry.isIntersecting && entry.intersectionRatio >= threshold;
    if (inView && !apiRequested) {
      apiRequested = true;
      window.onYouTubeIframeAPIReady = () => {
        new YT.Player(demoFrame, {
          events: {
            onReady(event) {
              demoPlayer = event.target;
              startDemo();
            },
          },
        });
      };
      const api = document.createElement("script");
      api.src = "https://www.youtube.com/iframe_api";
      document.head.append(api);
    }
    startDemo();
  }, { threshold });

  document.addEventListener("visibilitychange", startDemo);
  demoObserver.observe(demoFrame);
}
