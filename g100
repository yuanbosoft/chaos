import matplotlib.pyplot as plt
import cartopy.crs as ccrs
import cartopy.feature as cfeature
import numpy as np
from shapely.geometry import Point
import cartopy.io.shapereader as shpreader

# 创建一个使用 PlateCarree 投影的完整全球地图
fig = plt.figure(figsize=(12, 6))
ax = plt.axes(projection=ccrs.PlateCarree())

# 绘制地图的海岸线和国家边界
ax.coastlines()
ax.add_feature(cfeature.BORDERS, linestyle=':')

# 设置地图范围，确保显示整个世界
ax.set_global()

# 加载 Natural Earth 的陆地信息
land_shp = shpreader.natural_earth(resolution='110m', category='physical', name='land')
land_geom = list(shpreader.Reader(land_shp).geometries())

# 加载中国边界，用于排除中国境内的点
china_shp = shpreader.natural_earth(resolution='110m', category='cultural', name='admin_0_countries')
china_geom = [geom for record, geom in zip(shpreader.Reader(china_shp).records(), shpreader.Reader(china_shp).geometries()) if record.attributes['NAME'] == 'China'][0]

# 初始化存储有效点的列表
valid_points = []

# 生成100个随机节点的经纬度，确保它们分布在陆地上且不在中国境内
np.random.seed(42)  # 为了结果可重复性
while len(valid_points) < 100:
    lat = np.random.uniform(-60, 80)  # 纬度范围大致在 -60° 到 80°
    lon = np.random.uniform(-180, 180)  # 经度范围在 -180° 到 180°
    point = Point(lon, lat)
    
    # 检查点是否位于陆地上且不在中国境内
    if any(geom.contains(point) for geom in land_geom) and not china_geom.contains(point):
        valid_points.append((lon, lat))

# 将经纬度分离为两个列表
lons, lats = zip(*valid_points)

# 初始化每个节点的连接数
connections_count = [0] * len(valid_points)

# 在地图上绘制小红点节点，将节点大小减少到原来的1/4
ax.scatter(lons, lats, color='red', s=25, transform=ccrs.PlateCarree(), alpha=0.8)

# 创建网状结构，确保每个节点最多与8个其他节点相连
for i in range(len(valid_points)):
    for j in range(i + 1, len(valid_points)):
        if connections_count[i] < 8 and connections_count[j] < 8 and np.random.rand() < 0.1:
            ax.plot([lons[i], lons[j]], [lats[i], lats[j]], color='blue', linewidth=0.5, transform=ccrs.PlateCarree(), alpha=0.6)
            connections_count[i] += 1
            connections_count[j] += 1

# 设置地图显示完整的全球区域
ax.set_extent([-180, 180, -90, 90], crs=ccrs.PlateCarree())

plt.title('100 Blockchain Nodes with Up to 8 Connections Each (Excluding China)')
plt.show()
