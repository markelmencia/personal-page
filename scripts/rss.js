import RSS from 'rss'
import fs from 'fs'
import matter from 'gray-matter'
import { remark } from 'remark'
import remarkHtml from 'remark-html'

const feed = new RSS({
  title: "Markel Mencía's blog",
  description: "Markel's blog, mainly focused on Computer Science but also about other topics.",
  site_url: 'https://markelmencia.com',
  feed_url: 'https://markelmencia.com/rss.xml',
  language: 'en',
})

  const blogFiles = fs.readdirSync('posts')
  const blogs = await Promise.all(
    blogFiles.map(async (filename) => {
      const slug = filename.replace('.md', '')
      const readFiles = fs.readFileSync(`posts/${filename}`, 'utf-8')
      const { data: frontMatter, content } = matter(readFiles)
      
      const processedContent = await remark().use(remarkHtml).process(content)
      var htmlContent = processedContent.toString()

      htmlContent = htmlContent.replace(/src="(?!https?:\/\/)([^"]+)"/g,
        (_, path) => {
          const fullPath = path.startsWith('/') ? path : `/${path}`
          return `src="https://markelmencia.com${fullPath}"`
        }
      )
        
      htmlContent = htmlContent.replace(/href="(?!https?:\/\/)([^"]+)"/g,
        (_, path) => {
          const fullPath = path.startsWith('/') ? path : `/${path}`
          return `href="https://markelmencia.com${fullPath}"`
        }
      )
      
      return {slug, frontMatter, htmlContent, type: "blog"}
    })
  )

  const writeupFiles = fs.readdirSync('writeups')
  const writeups = await Promise.all(
    writeupFiles.map(async (filename) => {
      const slug = filename.replace('.md', '')
      const readFiles = fs.readFileSync(`writeups/${filename}`, 'utf-8')
      const { data: frontMatter, content } = matter(readFiles)
      
      const processedContent = await remark().use(remarkHtml).process(content)
      var htmlContent = processedContent.toString()

      htmlContent = htmlContent.replace(/src="(?!https?:\/\/)([^"]+)"/g,
        (_, path) => {
          const fullPath = path.startsWith('/') ? path : `/${path}`
          return `src="https://markelmencia.com${fullPath}"`
        }
      )
        
      htmlContent = htmlContent.replace(/href="(?!https?:\/\/)([^"]+)"/g,
        (_, path) => {
          const fullPath = path.startsWith('/') ? path : `/${path}`
          return `href="https://markelmencia.com${fullPath}"`
        }
      )
      
      return {slug, frontMatter, htmlContent, type: "writeups"}
    })
  )

  const allPosts = [...blogs, ...writeups]

  const sortedPosts = allPosts.sort((a, b) => {
  return new Date(b.frontMatter.date) - new Date(a.frontMatter.date)
})

sortedPosts.forEach((post) => {
  feed.item({
    title: post.frontMatter.title,
    description: post.htmlContent,
    url: `https://markelmencia.com/${post.type}/${post.slug}`,
    date: post.frontMatter.date,
  })
})

fs.writeFileSync('./public/rss.xml', feed.xml({ indent: true }))