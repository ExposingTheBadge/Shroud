#include "sparkline_widget.h"
#include <QPainter>
#include <QPainterPath>

SparklineWidget::SparklineWidget(QWidget *parent) : QWidget(parent) {
    setAttribute(Qt::WA_OpaquePaintEvent, false);
}

void SparklineWidget::setSeries(const QVector<double> &samples) {
    m_series = samples;
    update();
}

void SparklineWidget::paintEvent(QPaintEvent *) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.fillRect(rect(), Qt::transparent);

    if (m_series.size() < 2) {
        p.setPen(QColor(0x55, 0x55, 0x55));
        p.drawText(rect(), Qt::AlignCenter, "—");
        return;
    }

    double lo = m_series.first(), hi = lo;
    for (double v : m_series) { if (v < lo) lo = v; if (v > hi) hi = v; }
    double span = hi - lo;
    if (span < 1e-9) span = 1.0;

    const int margin = 2;
    const double w = qMax(1, width()  - 2 * margin);
    const double h = qMax(1, height() - 2 * margin);
    const double step = w / double(m_series.size() - 1);

    QPainterPath line;
    QPainterPath area;
    for (int i = 0; i < m_series.size(); ++i) {
        double x = margin + i * step;
        double y = margin + h - ((m_series[i] - lo) / span) * h;
        if (i == 0) { line.moveTo(x, y); area.moveTo(x, margin + h); area.lineTo(x, y); }
        else        { line.lineTo(x, y); area.lineTo(x, y); }
    }
    area.lineTo(margin + (m_series.size() - 1) * step, margin + h);
    area.closeSubpath();

    p.fillPath(area, m_fill);
    p.setPen(QPen(m_line, 1.6));
    p.drawPath(line);
}
