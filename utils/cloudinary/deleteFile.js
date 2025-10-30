import cloudinary from './config.js';

export const deleteMultipleFiles = async (publicIds, type, batchSize = 50) => {
  console.log(publicIds);
  if (!publicIds || !Array.isArray(publicIds) || publicIds.length === 0) {
    throw new Error('Array of public_ids is required');
  }

  const results = [];
  const res_type = type === 'image' ? 'image' : 'raw';
  // Split publicIds into batches
  for (let i = 0; i < publicIds.length; i += batchSize) {
    const batch = publicIds.slice(i, i + batchSize);

    // Delete all files in this batch in parallel
    const batchResults = await Promise.all(batch.map((id) => cloudinary.uploader.destroy(id, {
      resource_type: res_type
    })));
    results.push(...batchResults);
  }

  return results;
};
