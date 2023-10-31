#author muyuan.y yufeng.s
# python3 mypod-lifecycle.py --podname jpprod-oversea-user-message-server-0 --logfile messages --eventlevel Info,Normal,Warning,Error,Fatal

import argparse
from typing import List
import matplotlib.pyplot as plt
import numpy as np
import re
import datetime
import pandas as pd
from collections import Counter
from matplotlib.backend_bases import PickEvent
import math
import logging
from matplotlib.widgets import Slider

plt.rcParams['font.sans-serif'] = ['SimHei', 'Songti SC', 'STFangsong']
plt.rcParams['axes.unicode_minus'] = False
parser = argparse.ArgumentParser(description="display pod lifecycle")
parser.add_argument("--podname", default=None, type=str, help="name of pod, default=None")
parser.add_argument("--logfile", default=None, type=str, help="log file path of pod, default=None")
parser.add_argument("--eventlevel", default="Normal,Warning,Error,Fatal",
                    type=str,
                    help="event level configure in POD_EVENT_CONFIG::level_desc, default=Normal,Warning,Error,Fatal")
parser.add_argument("--loggerlevel", default="INFO", type=str, help="script runtime logger level, default=INFO")
args = parser.parse_args()

LOG_LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING
}


class MyLogger:
    def __init__(self, log_level=LOG_LEVEL_MAP.get(args.loggerlevel)):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)

        formatter = logging.Formatter('[%(asctime)s] - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)

        self.logger.addHandler(console_handler)

    def info(self, message):
        self.logger.info(message)

    def error(self, message):
        self.logger.error(message)

    def debug(self, message):
        self.logger.debug(message)

    def warning(self, msg):
        self.logger.warning(msg)


logger = MyLogger()
# 标签描述默认显示如下level中等级最高的颜色和level描述
LEVEL_MAP = {
    'Info': 0,
    'Normal': 1,
    'Warning': 2,
    'Error': 3,
    'Fatal': 4
}
# 不同level的显示颜色mapping
COLOR_MAP = {
    'Info': 'whitesmoke',  # 灰色
    'Normal': 'lightgreen',  # 亮绿色
    'Warning': 'darkorange',  # 橙黄色
    'Error': 'red',
    'Fatal': 'darkred'
}
# alias是展示名称，如果不写默认使用log里匹配的key
POD_EVENT_CONFIG = {
    'Container started': {
        'level_desc': "Normal"
    },
    'Created container': {
        'bbox_color_show': 'lightgreen',
        'level_desc': "Normal"
    },
    'Started container': {
        'bbox_color_show': 'lightgreen',
        'level_desc': "Normal"
    },
    'SyncLoop ADD': {
        'alias': 'ADD POD',
        'level_desc': "Normal"
    },
    'SyncLoop UPDATE': {
        'alias': 'Update POD',
        'level_desc': "Normal"
    },
    'SyncLoop DELETE': {
        'alias': 'Delete POD',
        'level_desc': "Normal"
    },
    'Probe succeeded': {
        'bbox_color_show': 'whitesmoke',
        'level_desc': "Info"
    },
    'Reason:ContainersNotReady': {
        'alias': 'ContainersNotReady',
        'level_desc': "Warning"
    },
    'Readiness probe failed': {
        'alias': 'Readiness failed',
        'level_desc': "Warning"
    },
    'Liveness probe failed': {
        'alias': 'Liveness failed',
        'level_desc': "Warning"
    },
    'Killing unwanted container': {
        'alias': 'Killing unwanted',
        'level_desc': "Warning"
    },
    'Container exited normally': {
        'alias': 'Container exited',
        'level_desc': "Normal"
    },
    'Killing container': {
        'bbox_color_show': '#FFA500',
        'level_desc': "Warning"
    },
    'will be restarted': {
        'alias': 'Pod restart',
        'level_desc': "Warning"
    },
    'SyncLoop REMOVE': {
        'alias': 'REMOVE POD',
        'level_desc': "Normal"
    },
    'Pod was deleted and then recreated': {
        'alias': 'Pod Recreated',
        'level_desc': "Warning"
    },
    'Pod has been deleted and must be killed': {
        'alias': 'Pod delete & kill',
        'level_desc': "Normal"
    },
    'Pod does not exist on the server': {
        'alias': 'Pod not exist',
        'level_desc': "Normal"
    },
}

def config_check_and_process():
    for k, v in POD_EVENT_CONFIG.items():
        try:
            # assert v['bbox_color_show'], f'event: [{k}] has no attribute "bbox_color_show"'
            # 匹配level的优先级
            level = LEVEL_MAP[v['level_desc']]
            POD_EVENT_CONFIG[k]['level'] = level
            # 匹配level的颜色
            color = COLOR_MAP[v['level_desc']]
            POD_EVENT_CONFIG[k]['bbox_color_show'] = color
            # 如果没有设置alias(展示用) 默认用event名
            if not v.get('alias'):
                POD_EVENT_CONFIG[k]['alias'] = k
        except Exception as e:
            logger.error('config setting error')
            logger.error(e)
    logger.info('config dict check done')


config_check_and_process()


class EventCounter(Counter):

    def __str__(self) -> str:
        super().__str__()
        _infos = []
        for _k, _v in self.items():
            _infos.append(str(_k) + ':' + str(_v))
        return '\n'.join(_infos)


def event_agg(events: pd.Series) -> pd.Series:
    event_list = events.to_list()
    event_info = sorted([(
        POD_EVENT_CONFIG.get(event).get('level'),
        POD_EVENT_CONFIG.get(event).get('bbox_color_show'),
        POD_EVENT_CONFIG.get(event).get('level_desc'),
        POD_EVENT_CONFIG.get(event).get('alias'),
    ) for event in event_list], key=lambda x: x[0], reverse=True)
    alias_list = [_[3] for _ in event_info]
    event_counter = EventCounter(alias_list)

    return pd.Series(
        {
            'event_infos': '\n'.join(event_list),
            'event_counter': str(event_counter),
            'event_size': len(event_list),
            'bbox_color_show': event_info[0][1],  # 每秒取最高
            'level_desc': event_info[0][2],  # 每秒取最高
            'alias': '->\n'.join(alias_list)
        }
    )


def draw_time_text(events: List[str], dates: List[datetime.datetime]):
    event_df = pd.DataFrame({"event": events, "dates": dates})  # .to_clipboard()
    g = event_df['dates'].apply(lambda x: datetime.datetime.strftime(x, "%m-%d %H:%M:%S"))
    grouped = event_df.groupby(g)
    # for _g, _df in grouped:
    #     print(_g, _df)
    event_summary = grouped.apply(
        lambda x: event_agg(x['event'])
    )

    # 图表所需信息
    _ylabel = []
    _xlim = []
    _levels = []
    _vert = []
    _color = []
    cnt = 0
    click_content = []
    svg_content = []

    for index, row in event_summary.iterrows():
        info = ''
        if row['event_size'] >= 2:
            info += row['event_counter'] + f'\n等级:' + row['level_desc']
            svg_content.append((row['alias'].replace('\n', ' '), cnt + 1))
        else:
            info += row['alias'] + '\n等级:' + row['level_desc']
        _ylabel.extend([info, index])
        _xlim.extend([cnt + 1, cnt + 1])
        # _levels.extend([-3, 0]) if (cnt % 2 == 0) else _levels.extend([3, 0])

        if cnt % 2 == 0:
            _levels.extend([-1.5, 0]) if cnt % 4 < 2 else _levels.extend([-3, 0])
        else:
            _levels.extend([1.5, 0]) if cnt % 4 < 2 else _levels.extend([3, 0])

        _vert.extend(['top', 'bottom']) if cnt % 2 == 0 else _vert.extend(['bottom', 'top'])
        _color.extend([row['bbox_color_show'], 'lightgreen'])
        click_content.append(row['alias'].replace('\n', ' '))
        cnt += 1

    fig, ax = plt.subplots(figsize=(100, 10), constrained_layout=True)
    # 标题
    ax.set(title=f'Pod-lifecycle {args.podname}')

    # 添加线条, basefmt设置中线的颜色，linefmt设置线的颜色以及类型
    # 初步设想：level需要比较均匀的铺在这个上面，直接生成等差数列 然后用标签显示时间 和事件
    markerline, stemline, baseline = ax.stem(_xlim, _levels,
                                             linefmt="#00BFFF", basefmt="green",
                                             )
    # 交点空心,zorder=3设置图层,mec="k"外黑 mfc="w"内白
    plt.setp(markerline, mec='#00FF00', mfc="w", zorder=3)

    # 通过将Y数据替换为零，将标记移到基线
    markerline.set_ydata(np.zeros(len(_xlim)))

    # 添加文字注释
    for d, l, r, va, color in zip(_xlim, _levels, _ylabel, _vert, _color):
        logger.debug(f'annotate location param: \nd: {d}\nl: {l}\nr: {r}\nva: {va}\ncolor: {color}\n')
        ax.annotate(r, xy=(d, l),
                    xytext=(0, np.sign(l) * 3 - 5 if d % 2 == 0 else 5),
                    textcoords="offset points",
                    va=va, ha="center",
                    bbox=dict(boxstyle='round', facecolor=color, edgecolor='none', pad=0.2 if l == 0 else 0.8))

    # 设置图表的x轴范围为最小和最大日期
    ax.set_xlim(min(_xlim) - 3, max(_xlim) + 3)
    ax.set_ylim(-5, 5)
    # 逆时针30度，刻度右对齐
    # plt.setp(ax.get_xticklabels(), rotation=30, ha="right")

    # 隐藏轴线
    ax.get_yaxis().set_visible(False)
    ax.get_xaxis().set_visible(False)
    # 隐藏边框
    for spine in ["left", "top", "right", "bottom"]:
        ax.spines[spine].set_visible(False)
    # 边距仅设置y轴
    ax.margins(y=0.3)

    # svg本地保存图片 需要添加脚注
    svg_text_objs = []
    for idx, (_content, _x) in enumerate(svg_content, start=1):
        logger.debug(f'[{idx}] writing text description on x={_x} desc:{_content}')
        _adj_diff = 0.4
        _text_y_lim = _levels[_x * 2 - 2] + _adj_diff if _levels[_x * 2 - 2] < 0 else _levels[_x * 2 - 2] - _adj_diff
        _text = ax.text(_x, _text_y_lim, f'[{_ylabel[_x * 2 - 1]}] {_content}', fontsize=12, ha="center")
        svg_text_objs.append(_text)

    # 根据需要进行图表的调整和保存
    plt.tight_layout()
    plt.savefig(f'{args.podname}-Pod-lifecycle.svg')
    logger.info(f'save local image: {args.podname}-Pod-lifecycle.svg')
    if len(_xlim) >= 400:
        logger.warning(
            """
            Too many X-axis elements may cause local image display to be congested. 
            You can adjust the `figsize` bigger than (100,10) default 
            or use the `eventlevel` parameter to filter events with low prompt levels
            """)
    # 控件点击事件即可显示全，删掉这部分展示仅用于绘制本地图片
    while svg_text_objs:
        _delete = svg_text_objs.pop()
        _delete.remove()

    # click回调设置
    clicks = []

    def on_pick(event: PickEvent):
        logger.info(event.mouseevent)
        if clicks:
            click = clicks.pop()
            click.remove()
        if event.mouseevent.button == 1 and event.mouseevent.dblclick == 0:
            x = event.mouseevent.xdata
            x_idx = math.floor(x + 0.5) - 1
            logger.debug(f'content x index: {x_idx}')
            if 0 <= x_idx <= len(click_content) - 1:
                msg = click_content[x_idx]
            else:
                msg = '请点击时间轴内的时间或事件描述以展示具体细节'
            logger.debug(f'content display: {msg}')
            click = ax.text(x_idx, 4.5, f'{msg}', fontsize=16, ha="center")
            clicks.append(click)
        plt.draw()

    ax.set_picker(True)
    fig.canvas.mpl_connect('pick_event', on_pick)

    # 创建一个Slider对象，用于控制横向拖拽
    ax_slider = plt.axes([0.1, 0.1, 0.65, 0.03])
    slider = Slider(ax_slider, '时间轴', min(_xlim) - 5, max(_xlim), valinit=0, valstep=0.01)
    # 默认展示前20
    ax.set_xlim(min(_xlim), min(_xlim) + 20)

    # slider hook
    def slider_update(val):
        # 获取Slider的值
        x_range = slider.val
        if x_range == min(_xlim) - 5:
            ax.set_xlim(min(_xlim) - 5, max(_xlim) + 5)
            logger.debug(
                f'slider info: xlim({x_range},) label(展示总览,)')
            slider.valtext.set_text('展示总览')
        else:
        # 更新图形的x轴范围
            ax.set_xlim(x_range, x_range + 20)
            x_show_left = math.floor(min(_xlim) if x_range < min(_xlim) else x_range)
            x_show_right = math.floor(max(_xlim) if x_range + 20 > max(_xlim) else x_range + 20)
            # print(x_show_left, x_show_right)
            slider_label_show_left = _ylabel[x_show_left * 2 - 1]
            slider_label_show_right = _ylabel[x_show_right * 2 - 1]
            logger.debug(
                f'slider info: xlim({x_show_left},{x_show_right}) label({slider_label_show_left},{slider_label_show_right})')
            slider.valtext.set_text(' ~\n   '.join([slider_label_show_left, slider_label_show_right]))
        fig.canvas.draw_idle()

    slider.on_changed(slider_update)

    plt.show()
    plt.show()


if __name__ == '__main__':
    target_keywords = POD_EVENT_CONFIG.keys()
    dates = []
    events = []
    event_level_filter = args.eventlevel.split(',')
    with open(args.logfile, 'r') as file:
        for line in file:
            if args.podname in line:
                for keyword in target_keywords:
                    if POD_EVENT_CONFIG.get(keyword).get('level_desc') in event_level_filter:
                        match = re.search(r'(\w{3} \d{2} \d{2}:\d{2}:\d{2}).+' + '{}'.format(keyword), line)
                        if match:
                            # dates.append(match.group(1))
                            dates.append(datetime.datetime.strptime(match.group(1), "%b %d %H:%M:%S"))
                            events.append(keyword)
                            break
    if len(dates) == len(events) != 0:
        draw_time_text(events, dates)
    else:
        logger.error('event list is empty or log file is Incomplete')
        raise ValueError(f'data length: dates={len(dates)} events={len(events)} ,pleas check')
