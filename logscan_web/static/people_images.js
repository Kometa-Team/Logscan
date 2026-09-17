window.PeopleImages = {
  noImage(message = "No TMDb images found") {
    const element = document.createElement("div");
    element.className = "no-image";
    element.textContent = message;
    return element;
  },
  imageCard(image) {
    const tile = document.createElement("div");
    tile.className = "image-tile";
    const link = document.createElement("a");
    link.className = "person-image";
    link.href = image.download_url;
    link.target = "_blank";
    link.rel = "noopener";
    link.title = "View the original image";
    const imageElement = document.createElement("img");
    imageElement.src = image.preview_url;
    imageElement.alt = image.alt || "Profile image";
    imageElement.loading = "lazy";
    link.append(imageElement);
    const imageFrame = document.createElement("div");
    imageFrame.className = "image-frame";
    const download = document.createElement("a");
    download.className = "image-download";
    download.href = image.download_url;
    download.download = "";
    download.target = "_blank";
    download.rel = "noopener";
    download.title = "Download original image";
    download.setAttribute("aria-label", "Download original image");
    download.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v11m0 0 4-4m-4 4-4-4M5 17v3h14v-3"/></svg>';
    imageFrame.append(link, download);
    tile.append(imageFrame);
    if (image.label) {
      const label = document.createElement("div");
      label.className = "image-label";
      label.textContent = image.label;
      tile.append(label);
    }
    return tile;
  },
  googleImageSearchTile(name) {
    const parameters = new URLSearchParams({
      q: name,
      as_st: "y",
      imgar: "t|xt",
      udm: "2",
      tbs: "itp:face,qdr:y",
    });
    const link = document.createElement("a");
    link.className = "image-tile google-image-search-tile";
    link.href = `https://www.google.co.uk/search?${parameters}`;
    link.target = "_blank";
    link.rel = "noopener";
    const image = document.createElement("img");
    image.src = "/static/google.jpg";
    image.alt = "Google Image Search";
    image.loading = "lazy";
    const label = document.createElement("div");
    label.className = "image-label";
    label.textContent = "Google Image Search";
    link.append(image, label);
    return link;
  },
};
